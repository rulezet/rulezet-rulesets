rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_246_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_246_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9043ac8c5c2ab27fdfa470c055a497c24d8c18c63a6da6c44e3aea6220f3f08"

  strings:
    $s1 = "G;IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}