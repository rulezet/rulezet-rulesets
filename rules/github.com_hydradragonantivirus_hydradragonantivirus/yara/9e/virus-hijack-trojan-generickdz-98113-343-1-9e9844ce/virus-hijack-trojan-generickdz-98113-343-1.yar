rule Virus_Hijack_Trojan_GenericKDZ_98113_343_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_343_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83693ad59be92aa60df338a7a3fd6375478d7de0fcc2a761a30c01a899d481de"

  strings:
    $s1 = "BAlL{N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}