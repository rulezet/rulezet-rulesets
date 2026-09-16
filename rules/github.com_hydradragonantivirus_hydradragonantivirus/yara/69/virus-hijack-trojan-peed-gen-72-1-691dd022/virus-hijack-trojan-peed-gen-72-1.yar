rule Virus_Hijack_Trojan_Peed_Gen_72_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_72_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb9f8834106a6c1c9f85fc7ac7a58a6fae850a5b9e8d60c78a1d1c0c72fe92de"

  strings:
    $s1 = "nAzE%CV" fullword ascii
    $s2 = "a<acId" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}