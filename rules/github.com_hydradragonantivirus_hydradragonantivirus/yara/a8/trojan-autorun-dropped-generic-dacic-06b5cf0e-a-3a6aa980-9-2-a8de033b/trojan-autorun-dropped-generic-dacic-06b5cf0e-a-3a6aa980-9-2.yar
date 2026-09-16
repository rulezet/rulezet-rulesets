rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_9_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "788be98119badc70b8222ab76b865254e57ba43e7619745e617f5c7a72386c1d"

  strings:
    $s1 = "PorT%P" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}