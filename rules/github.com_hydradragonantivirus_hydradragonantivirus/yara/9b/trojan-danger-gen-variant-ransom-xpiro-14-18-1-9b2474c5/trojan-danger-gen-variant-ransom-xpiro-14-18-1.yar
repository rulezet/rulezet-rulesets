rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_18_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "381b803a18a0ee1ef092eca33fad4a3cda7b1b576bb91e67637e52bdcd67bb2f"

  strings:
    $s1 = "0dorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}