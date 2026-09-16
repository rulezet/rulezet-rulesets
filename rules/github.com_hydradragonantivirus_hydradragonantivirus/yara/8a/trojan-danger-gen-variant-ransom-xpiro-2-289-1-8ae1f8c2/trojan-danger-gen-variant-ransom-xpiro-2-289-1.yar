rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_289_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_289_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b13651dd6e3066b0cafa187fb02887ca95ef5840172777e07d567977080d622"

  strings:
    $s1 = "*IRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}