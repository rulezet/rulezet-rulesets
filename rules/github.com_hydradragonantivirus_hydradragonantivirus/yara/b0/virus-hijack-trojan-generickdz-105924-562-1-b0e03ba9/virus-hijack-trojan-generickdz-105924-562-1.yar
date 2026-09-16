rule Virus_Hijack_Trojan_GenericKDZ_105924_562_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_562_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d2680aa7ae8aca8a9abb131ccfaa17ebd52553fc159d31af9bcf94a48c0d103"

  strings:
    $s1 = "<Riva)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}