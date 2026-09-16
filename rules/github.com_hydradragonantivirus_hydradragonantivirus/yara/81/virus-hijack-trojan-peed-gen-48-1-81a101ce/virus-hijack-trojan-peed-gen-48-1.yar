rule Virus_Hijack_Trojan_Peed_Gen_48_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_48_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35fc7a133c7bf4596f24b35fcf8d40d6094326666b366d869af38fc59f03ca91"

  strings:
    $s1 = "L<rANe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}