rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_37_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_37_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2751f0e5d9005eb01b660c7ba97944a10c6a50d033ac0041180e924dfee4f073"

  strings:
    $s1 = "Cmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}