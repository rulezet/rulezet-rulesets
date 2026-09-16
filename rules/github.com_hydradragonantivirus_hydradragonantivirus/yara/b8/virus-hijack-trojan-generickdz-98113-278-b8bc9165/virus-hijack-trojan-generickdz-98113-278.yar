rule Virus_Hijack_Trojan_GenericKDZ_98113_278 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_278.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79722a179a17ef4bbf9940db0f0f86edb51789aca47d0f4f497395a67775fb16"

  strings:
    $s1 = "Trade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data,`" fullword ascii
    $s2 = "p@assets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}