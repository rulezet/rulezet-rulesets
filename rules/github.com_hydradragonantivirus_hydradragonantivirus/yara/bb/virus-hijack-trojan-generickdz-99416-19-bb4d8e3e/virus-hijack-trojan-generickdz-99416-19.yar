rule Virus_Hijack_Trojan_GenericKDZ_99416_19 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c068f45acf01ec5d2f4ed712ef2710ad868374001ac88ea830c6d26083d3bc69"

  strings:
    $s1 = "UUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}