rule Virus_Hijack_Trojan_GenericKDZ_103285_658 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_658.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b2e72ae56fdada13e1d2d43bb78d3b5dbbe48eafe4274321695723e7f512016"

  strings:
    $s1 = "-virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}