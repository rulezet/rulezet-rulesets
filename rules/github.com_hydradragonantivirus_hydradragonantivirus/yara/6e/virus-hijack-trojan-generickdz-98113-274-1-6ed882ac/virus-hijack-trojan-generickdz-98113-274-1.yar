rule Virus_Hijack_Trojan_GenericKDZ_98113_274_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_274_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e85a7d757c135f207285e9fb21ce40b585ef16c386e9988b54093e618b93aa9"

  strings:
    $s1 = "smUG?>GM" fullword ascii
    $s2 = "BElY*`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}