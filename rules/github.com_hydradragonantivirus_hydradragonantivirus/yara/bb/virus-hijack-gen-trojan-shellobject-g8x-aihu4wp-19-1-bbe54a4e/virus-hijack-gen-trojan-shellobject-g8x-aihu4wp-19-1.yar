rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_19_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "631f9334ed9c4d280b132a6122645951b60885f884b7a146e8ddd11f22f3b9ed"

  strings:
    $s1 = "Redeal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}