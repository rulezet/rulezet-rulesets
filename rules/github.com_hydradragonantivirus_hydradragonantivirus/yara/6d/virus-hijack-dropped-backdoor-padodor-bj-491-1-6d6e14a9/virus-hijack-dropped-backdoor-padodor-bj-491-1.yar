rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_491_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_491_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c91f4292835e4be8fe36354e926c00b78f957941c32bd00c7e34961fbf6301c"

  strings:
    $s1 = "slIm]lZ" fullword ascii
    $s2 = "D`LERP" fullword ascii
    $s3 = "BAck]~" fullword ascii
    $s4 = "SnUG#K" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}