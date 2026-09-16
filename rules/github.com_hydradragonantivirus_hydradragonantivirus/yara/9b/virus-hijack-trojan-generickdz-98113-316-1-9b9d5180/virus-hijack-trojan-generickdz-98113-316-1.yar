rule Virus_Hijack_Trojan_GenericKDZ_98113_316_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_316_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95fe0848822813a8fab6afa2210fc9885d07a37002a7b6aa6721fa6bd5036065"

  strings:
    $s1 = "Tx>Pise;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}