rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1271a9d5160a73a7a95a52a4990b122231ef877227000d8b99a8602b1bbe3f03"

  strings:
    $s1 = "%Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}