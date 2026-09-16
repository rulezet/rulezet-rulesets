rule Virus_Hijack_Trojan_GenericKDZ_103285_307 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_307.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d09af4e6fd85ff33b084f73e29928940d5816a1ea38a7da109df3127715ae92"

  strings:
    $s1 = "RUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}