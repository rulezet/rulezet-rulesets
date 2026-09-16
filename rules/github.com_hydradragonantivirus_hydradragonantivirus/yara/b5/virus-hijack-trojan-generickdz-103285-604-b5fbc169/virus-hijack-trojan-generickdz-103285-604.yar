rule Virus_Hijack_Trojan_GenericKDZ_103285_604 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_604.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d87f9e1dc5bd1061156a963af0e16d443e3c3882dc0a015e2a00b6beaf689eb"

  strings:
    $s1 = "<wOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}