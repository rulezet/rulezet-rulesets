rule Virus_Hijack_Trojan_GenericKDZ_98113_55_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_55_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "daee5873bae1b627fc557413c3c7abde0f84eb51cba94c3e7520b7114eaf3560"

  strings:
    $s1 = "s;PalL[.8@m" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}