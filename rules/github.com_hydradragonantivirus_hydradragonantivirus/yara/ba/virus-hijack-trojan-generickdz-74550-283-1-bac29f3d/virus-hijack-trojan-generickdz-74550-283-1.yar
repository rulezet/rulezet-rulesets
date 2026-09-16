rule Virus_Hijack_Trojan_GenericKDZ_74550_283_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_283_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f03903aada9a63c75685dbc0faf0bde2f3abb14ecc42b6e446bb82bbe72040a4"

  strings:
    $s1 = "RaKh`NvV" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}