rule Virus_Hijack_Trojan_GenericKDZ_103285_145 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_145.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43782f3cc8c6ced29e529e1f2c947644563b86c5fcd87d1f937b893af013ed50"

  strings:
    $s1 = "yOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}