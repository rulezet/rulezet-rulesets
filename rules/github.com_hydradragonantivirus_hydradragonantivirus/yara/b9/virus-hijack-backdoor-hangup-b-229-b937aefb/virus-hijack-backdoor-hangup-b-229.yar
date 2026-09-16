rule Virus_Hijack_Backdoor_Hangup_B_229 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_229.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3b74f60938e07071d84ce5d1c6c229bbd2e3c15287ae2496fcfd1e2c1a40320"

  strings:
    $s1 = "Msoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}