rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_3_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62d2c67b631111c620b309bca97816019f6765747f0e44be1c89eea2c052d6a7"

  strings:
    $s1 = "KagU@_>4" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}