rule Virus_Hijack_Backdoor_Hangup_B_55 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_55.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4c7826c0d1e4f08c39649cdf898f3e366c80e55ddef56f0328fe23738868a6b"

  strings:
    $s1 = "Ssoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}