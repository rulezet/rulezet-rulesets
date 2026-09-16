rule Virus_Hijack_Trojan_GenericKDZ_98113_247_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_247_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e6fe45147df6a49d0c59fceb3ceab6c72aea33fd767d00ca5d8c5c0d87ca5b0"

  strings:
    $s1 = "WuSH(n<g" fullword ascii
    $s2 = "Holy*U/5 G5e" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}