rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_3_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de3ce429d66f7d842fe533e50b99fa92efed857f1cc801ce9afce7658e18907c"

  strings:
    $s1 = "zsoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}