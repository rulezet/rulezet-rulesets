rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_85_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_85_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ded80f2477c24a0619e5fef91e883661b156ce69e0d97b99001a7ab66e23b956"

  strings:
    $s1 = "UVThis agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principl" ascii
    $s2 = "UVThis agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principl" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}