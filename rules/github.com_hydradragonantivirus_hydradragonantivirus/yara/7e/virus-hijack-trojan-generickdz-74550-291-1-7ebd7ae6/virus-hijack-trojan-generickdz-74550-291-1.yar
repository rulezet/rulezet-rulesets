rule Virus_Hijack_Trojan_GenericKDZ_74550_291_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_291_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b7ab9a1f41bd5f82b5bc993eec8cd20d3c64ac954c6ef92f6dff4fb603e794e"

  strings:
    $s1 = "@gANT?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}