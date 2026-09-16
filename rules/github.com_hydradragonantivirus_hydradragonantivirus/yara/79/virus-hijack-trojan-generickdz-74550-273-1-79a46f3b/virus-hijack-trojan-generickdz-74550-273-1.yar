rule Virus_Hijack_Trojan_GenericKDZ_74550_273_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_273_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ab1d9a8f94af8f0a2866fbae02def6085d802d4f4d3a14f1c33ec0863ec86fd"

  strings:
    $s1 = "lavE`}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}