rule Virus_Hijack_Trojan_GenericKDZ_98388_170_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_170_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "537c348ca6edac11eeaad50fa0754a87eb7b69f571590aafd8a762e6555f60ab"

  strings:
    $s1 = "(g&ENoL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}