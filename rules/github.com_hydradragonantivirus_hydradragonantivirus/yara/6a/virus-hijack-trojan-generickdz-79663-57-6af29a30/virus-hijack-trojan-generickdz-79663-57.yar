rule Virus_Hijack_Trojan_GenericKDZ_79663_57 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_57.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89346eb60788a01af85be4075f203d0a87563e9897581270c9e5bf16fee8c7dc"

  strings:
    $s1 = "#this notice will include a copy of your agreemen" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}