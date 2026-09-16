rule Virus_Hijack_Trojan_GenericKDZ_74550_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "115a5a18691e088df919b8624359fdecf2b13d94809818e4127690889293e492"

  strings:
    $s1 = "(!AbUT*" fullword ascii
    $s2 = "!GauM'0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}