rule Virus_Hijack_Trojan_GenericKDZ_105924_364 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_364.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b68e5196c96c5021d3ff4fd8d797411549530cfe5fa1457e1c780e26f827a4a9"

  strings:
    $s1 = "oH_aChn5Ns:$Etna@iwAQttLBR^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}