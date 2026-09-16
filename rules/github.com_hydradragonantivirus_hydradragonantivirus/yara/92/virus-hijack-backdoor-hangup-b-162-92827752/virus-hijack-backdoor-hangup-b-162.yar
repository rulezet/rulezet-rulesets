rule Virus_Hijack_Backdoor_Hangup_B_162 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_162.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1c756f4768d2e95b7a97f35eeff88109dc3a3b4a8efd8329b7249979eae0c19"

  strings:
    $s1 = "o%software manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}