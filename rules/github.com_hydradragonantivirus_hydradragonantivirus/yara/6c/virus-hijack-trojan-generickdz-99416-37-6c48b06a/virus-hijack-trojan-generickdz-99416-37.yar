rule Virus_Hijack_Trojan_GenericKDZ_99416_37 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_37.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "483a1cabae59a0e6e7caaa14a735bf502988f823afefbd19ab19b17ecaa1edaf"

  strings:
    $s1 = "NUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}