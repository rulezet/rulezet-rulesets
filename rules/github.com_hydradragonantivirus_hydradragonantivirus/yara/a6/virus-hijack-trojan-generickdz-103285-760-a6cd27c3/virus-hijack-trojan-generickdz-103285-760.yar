rule Virus_Hijack_Trojan_GenericKDZ_103285_760 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_760.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0453277f1cf4a2ac36f3001e5bc40c29a65fc191f3650ac9e119b1a3b6789eb3"

  strings:
    $s1 = "8\"Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}