rule Virus_Hijack_Trojan_GenericKDZ_103285_446 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_446.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2f5ca307ec180ed27125a0049b6b67f6e087a66fdc714ff92a7bf69a7e2b696"

  strings:
    $s1 = ";Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}