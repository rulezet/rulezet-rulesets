rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_203_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_203_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fca2be748e4ff4e5a5aef615de19a040389ac04e56564f50b7aa8bf1631f39f"

  strings:
    $s1 = "#IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}