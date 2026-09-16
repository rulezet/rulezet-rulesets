rule Virus_Hijack_Trojan_GenericKDZ_98113_93_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_93_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42b5dae7f49984ef1dfc821b6992d49f9a3415c47225fa2aadcc63a20596ab68"

  strings:
    $s1 = "Z!Fosh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}