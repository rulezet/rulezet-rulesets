rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_34_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_34_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d3c495c50c6f0071551231e3da390d0dd2190113fbcfa18351f25980360b7a8"

  strings:
    $s1 = "84virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}