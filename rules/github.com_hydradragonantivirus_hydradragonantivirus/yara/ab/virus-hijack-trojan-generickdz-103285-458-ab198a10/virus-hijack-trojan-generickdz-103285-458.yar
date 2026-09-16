rule Virus_Hijack_Trojan_GenericKDZ_103285_458 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_458.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fc9619a50bb1df8b0a5955b1b1717915a0d2b9b32694e87ac8157d302d2155a"

  strings:
    $s1 = "kJOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}