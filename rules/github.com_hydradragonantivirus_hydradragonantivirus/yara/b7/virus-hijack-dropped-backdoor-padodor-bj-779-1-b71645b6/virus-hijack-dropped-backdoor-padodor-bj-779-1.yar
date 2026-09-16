rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_779_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_779_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b000b4741e255ab059125f5e0577b0ab184dbe644e318f1b6ee4117eb6231251"

  strings:
    $s1 = "leucoplakia" fullword wide
    $s2 = "8+6<FeEd" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}