rule Trojan_Autorun_Generic_Dacic_AAD0835C_A_866F9A53_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Dacic.AAD0835C.A.866F9A53_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f5279c284ddf20f4f9889531e541e167b4c492ebb5444b02ea31a1a3c5a86db"

  strings:
    $s1 = "3:4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}