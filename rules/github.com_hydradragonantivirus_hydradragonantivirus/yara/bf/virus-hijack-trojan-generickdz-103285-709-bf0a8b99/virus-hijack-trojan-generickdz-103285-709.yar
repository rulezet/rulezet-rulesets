rule Virus_Hijack_Trojan_GenericKDZ_103285_709 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_709.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38c61cdaafae25779c8328b3be44c567aa75f805f4234b610a3cd1943f4eb1b9"

  strings:
    $s1 = "TwOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}