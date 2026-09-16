rule Virus_Hijack_Backdoor_Hangup_B_75 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_75.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3af4fac902ea3dc1f4f8c52fa5b8af7a757be414f298e654c639135ca9eb103f"

  strings:
    $s1 = "ETrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}