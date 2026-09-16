rule Virus_Hijack_Trojan_GenericKDZ_94849_24_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0deebda9623e82f7dcb6f7fa2dd3e4c28d0c5a9a4ecb749290bbca48ee4c7db"

  strings:
    $s1 = "N{@TALE" fullword ascii
    $s2 = "Z!liFE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}