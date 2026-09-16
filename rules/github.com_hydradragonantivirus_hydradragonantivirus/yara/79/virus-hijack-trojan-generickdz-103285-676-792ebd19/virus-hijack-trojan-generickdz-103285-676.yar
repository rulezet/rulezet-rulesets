rule Virus_Hijack_Trojan_GenericKDZ_103285_676 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_676.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e21692b1cab02784787a660d10d5a3cda95d4e8cae89f48746965e40408879d"

  strings:
    $s1 = "7What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}