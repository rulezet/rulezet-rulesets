rule Virus_Hijack_Trojan_GenericKDZ_99416_40 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_40.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c42a87ea9660f03071b648881b27afe03e0d9d95eae5394ff4303a7818fbf09"

  strings:
    $s1 = "#User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}