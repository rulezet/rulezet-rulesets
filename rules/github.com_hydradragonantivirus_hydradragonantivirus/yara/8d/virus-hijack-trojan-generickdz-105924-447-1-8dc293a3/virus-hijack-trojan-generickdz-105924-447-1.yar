rule Virus_Hijack_Trojan_GenericKDZ_105924_447_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_447_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2880dfc9607bdefc612f9062600ca6b4d0d571bb38bf1714ee504d121be35523"

  strings:
    $s1 = "FAlX GD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}