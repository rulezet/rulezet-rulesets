rule Virus_Hijack_Trojan_GenericKDZ_105924_152_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_152_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84a3d149b8cc7ac936938d846b402f397fe5b802e7a569fba3bfbb757b6822a7"

  strings:
    $s1 = "dynamic method does not support fault clause" fullword wide
    $s2 = "Laragon - fast & powerful local development environment     " fullword wide
    $s3 = "StopBlock" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}