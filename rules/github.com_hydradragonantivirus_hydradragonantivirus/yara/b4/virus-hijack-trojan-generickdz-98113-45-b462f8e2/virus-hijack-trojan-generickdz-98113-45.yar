rule Virus_Hijack_Trojan_GenericKDZ_98113_45 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_45.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4a070916f3406e047bb9228bde4832d5c4eeb44168d60497ebe9ac658f18ecf"

  strings:
    $s1 = "94. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}