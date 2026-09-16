rule Trojan_Autorun_Gen_Variant_Fugrafa_3207_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Fugrafa.3207_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba015f4711b6b9b5266be413076d816d3f27f230fcddd8c1c1ff05a963c47120"

  strings:
    $s1 = "zor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}