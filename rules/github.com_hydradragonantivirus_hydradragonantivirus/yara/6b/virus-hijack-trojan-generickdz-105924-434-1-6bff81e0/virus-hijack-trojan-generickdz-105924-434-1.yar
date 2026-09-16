rule Virus_Hijack_Trojan_GenericKDZ_105924_434_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_434_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87e019a8af35f98d5f4de6a5a73a59c9b02bcabbe721a9d769ecc9b56cbb2b12"

  strings:
    $s1 = "<taRS;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}