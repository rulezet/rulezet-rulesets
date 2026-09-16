rule Virus_Hijack_Trojan_GenericKDZ_98388_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "baa6c5ea34881ec60e22b57846de48347669447172b20b66b523993f4b210f67"

  strings:
    $s1 = "#\\oM#COOt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}