rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_86_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_86_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b267aaca2b3f85f9110543a4dcb8bbee86bab89fab5bf1d7bbafe34e7389362"

  strings:
    $s1 = "peho,:64" fullword ascii
    $s2 = "e(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii
    $s3 = "e(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}