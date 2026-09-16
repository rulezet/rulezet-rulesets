rule Virus_Hijack_Trojan_GenericKDZ_98113_64_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_64_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8b7edc8ec914e46d52aff5878679f65a7ccbf0fa64350554ceabae2ba14585a"

  strings:
    $s1 = "0[wHee" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}