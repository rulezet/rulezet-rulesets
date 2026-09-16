rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_59_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_59_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e2f83cc65d18d0386fa16b6197783239bebdae05b911b2385b3ca2cfd85a419"

  strings:
    $s1 = "qIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}