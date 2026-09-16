rule Virus_Hijack_Trojan_GenericKDZ_74550_305 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_305.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4223037aeda9d2d409ba8c5b34b06c35aecd0723b3260468f02ade25b5fab9b4"

  strings:
    $s1 = "h&feme" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}