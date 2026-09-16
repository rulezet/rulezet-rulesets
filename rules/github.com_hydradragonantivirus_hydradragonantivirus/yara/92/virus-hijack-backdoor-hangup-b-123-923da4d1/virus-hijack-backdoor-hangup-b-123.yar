rule Virus_Hijack_Backdoor_Hangup_B_123 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_123.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65ca087744ee4e1ebf5a3449e55c7aaf5ebe2d2044c8a526b7c4d41959794d0a"

  strings:
    $s1 = "Trade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}