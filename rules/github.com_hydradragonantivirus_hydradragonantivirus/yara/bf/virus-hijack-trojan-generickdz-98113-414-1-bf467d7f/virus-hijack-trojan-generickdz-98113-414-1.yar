rule Virus_Hijack_Trojan_GenericKDZ_98113_414_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_414_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff1e1811e4963cca9d50e9bb239ea505eb1e2aca0b4edd95dd86cdfc4ff3f6de"

  strings:
    $s1 = "#&noUS" fullword ascii
    $s2 = "*EldIN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}