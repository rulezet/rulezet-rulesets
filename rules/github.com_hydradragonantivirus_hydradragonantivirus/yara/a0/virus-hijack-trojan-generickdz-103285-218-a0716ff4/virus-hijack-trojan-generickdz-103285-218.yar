rule Virus_Hijack_Trojan_GenericKDZ_103285_218 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_218.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f89fc825ada920e8bd2653c2ad439d97a1a5ddb1e9938aab936b2be44b52d6c4"

  strings:
    $s1 = "')Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}