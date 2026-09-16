rule Virus_Hijack_Trojan_GenericKDZ_74550_74_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_74_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1168f41156a794438a853de9fc6a25faf214f124015334d2b06dedfb2b410527"

  strings:
    $s1 = "XO}jHOw." fullword ascii
    $s2 = "{<TYND" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}