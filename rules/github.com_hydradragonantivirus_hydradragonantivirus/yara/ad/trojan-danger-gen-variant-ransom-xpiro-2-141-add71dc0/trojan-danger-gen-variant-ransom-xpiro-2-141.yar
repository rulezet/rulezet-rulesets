rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_141 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_141.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b20fbd80f031234a80ba500dd19fd82795a93b598a58923bdc184c4c8ce81de4"

  strings:
    $s1 = "Interactive Ruby.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}