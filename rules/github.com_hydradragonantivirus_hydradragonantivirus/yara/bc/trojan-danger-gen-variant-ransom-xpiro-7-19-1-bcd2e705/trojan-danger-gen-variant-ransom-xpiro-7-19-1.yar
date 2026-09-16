rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_19_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b957627ff91b90ed74900c16e2d77cc950aa55970e6d164e4a2727fc81356a0"

  strings:
    $s1 = ";xmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}