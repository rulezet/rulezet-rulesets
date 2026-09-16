rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_28_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_28_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6018e41b9ab6f5ccb1b369cd7440406dcc3d3c2bbaaa53060fbde9b6ee2a53c3"

  strings:
    $s1 = "Aorders during any 12 month period." fullword ascii
    $s2 = "m`%Goal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}