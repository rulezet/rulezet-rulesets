rule Virus_Hijack_Trojan_GenericKDZ_98113_356 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_356.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59399c0595185c9b4db6ad0026419e2c5893028921143b8a3b7cb46795ecc022"

  strings:
    $s1 = "9by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}