rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_47_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_47_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "148380efef60f9121b83ceb20536e18d3152f9ef0cdcf35f735a25392bb1054e"

  strings:
    $s1 = "$)orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}