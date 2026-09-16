rule Virus_Hijack_Trojan_GenericKDZ_105924_340_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_340_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28156ecc4a5cd25e2569770e9455aceff706d17b40c18b32af1fb42031afca08"

  strings:
    $s1 = "BHUT[-" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}