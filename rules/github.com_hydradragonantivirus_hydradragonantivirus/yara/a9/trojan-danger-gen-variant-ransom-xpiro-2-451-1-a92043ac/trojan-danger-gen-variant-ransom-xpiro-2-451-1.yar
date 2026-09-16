rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_451_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_451_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "607d0751ec8b716979e77d57c261a260e3f41016c4cfaf72ab85f563e0378294"

  strings:
    $s1 = "UAng'U>" fullword ascii
    $s2 = "emPT 1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}