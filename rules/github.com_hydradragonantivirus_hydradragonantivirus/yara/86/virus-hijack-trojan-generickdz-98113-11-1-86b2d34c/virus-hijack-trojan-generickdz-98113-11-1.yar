rule Virus_Hijack_Trojan_GenericKDZ_98113_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d037bd28c5021bd514f2d3e8cb7951d2b654fd95926df72769a891677c198360"

  strings:
    $s1 = "gOwN}+" fullword ascii
    $s2 = "Ou:Drug$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}