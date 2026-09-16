rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_6_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12e51703706b77dee4d0387f229c0a01ed4cf54c863ad48aeefa739e53261a93"

  strings:
    $s1 = "fSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}