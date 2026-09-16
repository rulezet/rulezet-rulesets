rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_352 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_352.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f20ad7ac7a8a826c7067878f1fb7e74335be735b03badc5906d06b5a3ee575d"

  strings:
    $s1 = ",If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}