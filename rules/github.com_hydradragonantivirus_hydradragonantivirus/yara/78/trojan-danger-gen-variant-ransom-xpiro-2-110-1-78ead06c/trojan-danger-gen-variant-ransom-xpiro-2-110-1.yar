rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_110_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_110_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8830d7d8fdd9c85f61384a57e8d14f90b5b03327506f8b30e2968fdcea11e2c6"

  strings:
    $s1 = "DoEr{8" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}