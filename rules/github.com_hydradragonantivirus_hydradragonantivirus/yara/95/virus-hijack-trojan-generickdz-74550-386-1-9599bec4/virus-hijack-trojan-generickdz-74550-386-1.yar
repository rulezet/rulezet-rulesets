rule Virus_Hijack_Trojan_GenericKDZ_74550_386_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_386_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c86987b896024d19e990f494d841b5fd413fc5f098daf9fbbbac7c63dc4a68b1"

  strings:
    $s1 = "boOL VO$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}