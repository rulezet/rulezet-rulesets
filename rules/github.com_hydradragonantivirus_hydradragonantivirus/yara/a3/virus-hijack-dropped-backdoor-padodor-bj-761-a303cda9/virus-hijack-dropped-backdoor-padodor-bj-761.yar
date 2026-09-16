rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_761 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_761.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e77602e63c6b3bb2ef09e47e01b62e0911fd4502a45809bf72e1fce8345c5360"

  strings:
    $s1 = ">are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}