rule Virus_Hijack_Trojan_GenericKDZ_74550_271 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_271.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d852fa65ae0cd7ab4e0da24068b971dc5a16fec0bdfa88d0565b105ba7b59a8"

  strings:
    $s1 = "Snub]\\!fCa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}