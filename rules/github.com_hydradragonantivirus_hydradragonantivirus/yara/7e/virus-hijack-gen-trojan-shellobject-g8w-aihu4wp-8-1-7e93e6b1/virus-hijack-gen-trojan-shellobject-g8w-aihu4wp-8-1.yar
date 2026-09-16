rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fffbd669ccfaca780362d00cc3d7b165bb9f68a3902dc1fa9a099ecb706f3adc"

  strings:
    $s1 = "retro face" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}