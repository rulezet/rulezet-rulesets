rule Trojan_Danger_Gen_Variant_Ransom_Babuk_86_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Babuk.86_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08acaa0ef04141d1ff7f921d974d0c38d1ae3ad0e528983dbfa3909fa4bebaea"

  strings:
    $s1 = "(IRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}