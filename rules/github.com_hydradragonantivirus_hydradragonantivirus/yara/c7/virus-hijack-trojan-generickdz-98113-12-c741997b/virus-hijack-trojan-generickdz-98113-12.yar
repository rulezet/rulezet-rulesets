rule Virus_Hijack_Trojan_GenericKDZ_98113_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9650e46c49a83b9795e326961e11235ced264aa8f940b430a1b2372726964034"

  strings:
    $s1 = "(by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}