rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_255_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_255_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "436f653d683dc5686267daebd45e47fb143364a93849a5cd4355976e61468674"

  strings:
    $s1 = "sorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}