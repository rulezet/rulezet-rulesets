rule Trojan_Autorun_Trojan_GenericKDZ_94847_133_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_133_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01ca9b79bb3f9e40ceb3d2a0b2a3913ae9939f88164382a560e756946b3fbafa"

  strings:
    $s1 = "l{whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}