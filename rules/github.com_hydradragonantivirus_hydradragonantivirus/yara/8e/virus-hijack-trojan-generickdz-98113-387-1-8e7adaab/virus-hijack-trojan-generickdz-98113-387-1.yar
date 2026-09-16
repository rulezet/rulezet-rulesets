rule Virus_Hijack_Trojan_GenericKDZ_98113_387_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_387_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ec3b29e52da324d6ad96339d02d492e26b776c8441a77e490c55c914482e603"

  strings:
    $s1 = "?dUkE{Ni" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}