rule Virus_Hijack_Trojan_GenericKDZ_74550_257_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_257_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a7d1c9c0683ec46dd210a3babb29ff66f60b0b82e60584edf5366e3af699519"

  strings:
    $s1 = "D?saNS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}