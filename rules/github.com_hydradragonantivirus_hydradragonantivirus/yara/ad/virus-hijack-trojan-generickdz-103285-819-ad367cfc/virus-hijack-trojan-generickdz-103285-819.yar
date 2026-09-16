rule Virus_Hijack_Trojan_GenericKDZ_103285_819 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_819.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d35fba4064cf47fbc4d270d8c8147f2712f75310ca254cfd4c9d0550f3e99cbc"

  strings:
    $s1 = "4Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}