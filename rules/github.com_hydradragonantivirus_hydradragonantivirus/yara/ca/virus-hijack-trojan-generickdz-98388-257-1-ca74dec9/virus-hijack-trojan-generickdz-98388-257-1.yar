rule Virus_Hijack_Trojan_GenericKDZ_98388_257_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_257_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08ccec9f446efeb66910b163fcb196d5f50f46f0a4758f326f750fb22b8e192f"

  strings:
    $s1 = "nUBILe" fullword ascii
    $s2 = ")&;fReiR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}