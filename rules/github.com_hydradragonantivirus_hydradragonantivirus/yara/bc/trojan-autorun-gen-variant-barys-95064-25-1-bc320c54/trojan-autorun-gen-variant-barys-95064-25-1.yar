rule Trojan_Autorun_Gen_Variant_Barys_95064_25_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.95064_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b1187f9d5a297f233af8bef30ec1538b240ee9d2fb507bb21071c6d1c58efc5"

  strings:
    $s1 = "9functionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}