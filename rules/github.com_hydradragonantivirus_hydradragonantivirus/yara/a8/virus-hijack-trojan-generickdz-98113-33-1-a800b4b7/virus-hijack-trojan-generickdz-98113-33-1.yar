rule Virus_Hijack_Trojan_GenericKDZ_98113_33_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_33_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1b741ee3d88b7b4dd0d106b8d00e0df5faa223daa589759ae590b8f8720051a"

  strings:
    $s1 = "y$kAsm" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}