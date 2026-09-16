rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_107 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_107.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d18c6231e25142349a04b2ffac744a5579dd5dfd2d62abb5068c2ab48210f97"

  strings:
    $s1 = "ey}u ;sxky}} :sidy:xv/ 2" fullword ascii
    $s2 = "sidy:Mi*s4M8aoe+Qzr=;" fullword ascii
    $s3 = "|If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}