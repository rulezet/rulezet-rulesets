rule Virus_Hijack_Trojan_GenericKDZ_74550_330_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_330_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "feed295b47991076d7842879cbcce3a8e8285d03e7712b1a3381766632d4dce0"

  strings:
    $s1 = "3!CIVE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}