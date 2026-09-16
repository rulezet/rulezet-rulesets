rule Virus_Hijack_Trojan_GenericKDZ_98113_68_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_68_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00855e24adfbfa39d92322c64398ab9c205137d43e861cdfbf7b36e51f56e7ea"

  strings:
    $s1 = "alIt'1<" fullword ascii
    $s2 = "Z#}jerk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}