rule Virus_Hijack_Trojan_GenericKDZ_105924_546_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_546_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89f1e802284749999a7bc517585256484ef2a55c9d939f9ab8b653ea28a9be68"

  strings:
    $s1 = ";fZ,ovAl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}