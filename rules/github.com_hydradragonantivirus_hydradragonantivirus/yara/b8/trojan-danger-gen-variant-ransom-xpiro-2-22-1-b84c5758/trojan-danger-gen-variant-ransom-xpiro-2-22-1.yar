rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_22_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04b08c58d924b442f6f42921090a51717262fbbeb2023db8450a3ccf46271cf5"

  strings:
    $s1 = "bautomatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}