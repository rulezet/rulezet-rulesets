rule Virus_Hijack_Trojan_GenericKDZ_98113_80_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_80_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9c59cd36fb175f465e96a0394f7598714e8f31873b116d12b4be43a22a58c19"

  strings:
    $s1 = "naIk} " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}