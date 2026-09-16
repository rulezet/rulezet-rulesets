rule Virus_Hijack_Trojan_GenericKDZ_105924_603_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_603_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30a2a1b8eb05eb1fa0d804e2f25193c88e527f3874e99e5eae5b824fafb6f561"

  strings:
    $s1 = " B(reIN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}