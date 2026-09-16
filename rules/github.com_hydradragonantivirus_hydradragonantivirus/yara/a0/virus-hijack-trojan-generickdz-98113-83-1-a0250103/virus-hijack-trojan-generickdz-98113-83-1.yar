rule Virus_Hijack_Trojan_GenericKDZ_98113_83_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_83_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c935ab0b9e479bfba01824b012856a239229010baec00aa367f9d71d203c2b1"

  strings:
    $s1 = "eSpy>37B[;" fullword ascii
    $s2 = "%:CEnT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}