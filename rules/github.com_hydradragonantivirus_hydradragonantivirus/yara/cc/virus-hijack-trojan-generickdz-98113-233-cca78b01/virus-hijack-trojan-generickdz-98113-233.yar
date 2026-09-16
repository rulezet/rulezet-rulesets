rule Virus_Hijack_Trojan_GenericKDZ_98113_233 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_233.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c10a1d48e9045743d9206adaded0e91625078bbae4432a56d548234c7f2be548"

  strings:
    $s1 = "hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}