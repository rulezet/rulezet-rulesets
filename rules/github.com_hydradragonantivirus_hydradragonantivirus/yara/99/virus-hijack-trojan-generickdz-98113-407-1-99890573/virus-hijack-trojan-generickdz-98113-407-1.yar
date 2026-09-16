rule Virus_Hijack_Trojan_GenericKDZ_98113_407_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_407_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dca1fd664541c4a0520bd3ad5e5b8ed629aa4e728079ce5bd67b549c254ce33f"

  strings:
    $s1 = "tOGS(\"" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}