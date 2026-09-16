rule Virus_Hijack_Trojan_GenericKDZ_79663 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e159172850e11c59bf1457b5413f887cb7702289c0a2363afaeba190ccd07873"

  strings:
    $s1 = "jthis notice will include a copy of your agreemen" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}