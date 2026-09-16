rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aCeX4wn_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCeX4wn_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f5607d0f7cb9951fe4f3fe207cc14653cd561159a91de5ff00c9c1eae45a094"

  strings:
    $s1 = "qUAn&!C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}