rule Virus_Hijack_Trojan_GenericKDZ_103285_492 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_492.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c79ba374d666e17ee30024c75e8120c2e4205256352e670edf9a3e4e335d5d56"

  strings:
    $s1 = "-Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}