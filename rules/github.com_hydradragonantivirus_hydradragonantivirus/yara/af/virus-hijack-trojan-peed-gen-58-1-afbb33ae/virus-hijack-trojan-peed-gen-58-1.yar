rule Virus_Hijack_Trojan_Peed_Gen_58_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_58_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "246b58277d3fc187b7681d4ebf77e202d71c060d22d865e8187d8f08954bb35a"

  strings:
    $s1 = "Y)netE]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}