rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef9e9bc325182d5a4536753df728c4314a1d963948560a1819d5da04b1627be9"

  strings:
    $s1 = "Medicable" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}