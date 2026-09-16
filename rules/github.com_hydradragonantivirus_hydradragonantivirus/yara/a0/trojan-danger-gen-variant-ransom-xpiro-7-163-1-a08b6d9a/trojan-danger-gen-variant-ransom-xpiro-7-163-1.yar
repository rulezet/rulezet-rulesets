rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_163_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_163_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "801b2f16227a361953d58250e17eaeaeb3c67d99a35e8fff466980d47cd9186a"

  strings:
    $s1 = "|remainder of Section B remaining in full force and effect." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}