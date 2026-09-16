rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_a4uiSHo_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@a4uiSHo_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86665f9740788376812476f9664010c811165fa45c388d3c11fc644793ec5621"

  strings:
    $s1 = "ation error" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}