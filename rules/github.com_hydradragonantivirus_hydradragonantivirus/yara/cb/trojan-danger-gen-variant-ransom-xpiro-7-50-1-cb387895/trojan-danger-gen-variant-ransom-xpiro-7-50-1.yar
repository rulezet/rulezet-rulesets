rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_50_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_50_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12c305228e7537884d178805345d1ba74a9fe09665be117cb865f66c13119a2d"

  strings:
    $s1 = "[%WaGe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}