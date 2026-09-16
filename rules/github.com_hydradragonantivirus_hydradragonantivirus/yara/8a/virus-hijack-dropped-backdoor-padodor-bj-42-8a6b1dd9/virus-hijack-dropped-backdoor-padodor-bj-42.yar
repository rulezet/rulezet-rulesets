rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_42 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_42.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20591e73e723d85e3db5d78f2c86671f5cac3d1ffb5581a6ccd697c9d227e35a"

  strings:
    $s1 = "Zare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}