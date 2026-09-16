rule Virus_Hijack_Trojan_GenericKDZ_74550_215_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_215_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4bbe0e102c398ceec196a7d785a6a3f905da069264df4540a9a5edfd9cdc3f4"

  strings:
    $s1 = "!%FoRe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}