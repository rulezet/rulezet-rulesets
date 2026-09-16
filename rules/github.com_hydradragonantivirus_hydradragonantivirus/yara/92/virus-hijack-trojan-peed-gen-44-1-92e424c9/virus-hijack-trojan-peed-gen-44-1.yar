rule Virus_Hijack_Trojan_Peed_Gen_44_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_44_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adebd770901e29eafc0a586a0d90c7cadd6ee147395c54bed21cba42dee7b91c"

  strings:
    $s1 = "`LANk," fullword ascii
    $s2 = "LIny,m" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}