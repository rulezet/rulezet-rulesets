rule Virus_Hijack_Backdoor_Hangup_B_49 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_49.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee1bf6c7a274149d130e93d0321321283cdd34e62a63f4167d3dfa2256c856d3"

  strings:
    $s1 = "&your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}