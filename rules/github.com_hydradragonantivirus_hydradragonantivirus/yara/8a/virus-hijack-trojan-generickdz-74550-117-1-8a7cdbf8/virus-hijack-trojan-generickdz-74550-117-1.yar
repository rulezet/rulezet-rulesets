rule Virus_Hijack_Trojan_GenericKDZ_74550_117_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_117_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90c921cc2a6280e318ded0aedddbb85ac41b8e9cfe3dc08486c657656e20cf71"

  strings:
    $s1 = "SugI?K" fullword ascii
    $s2 = "F6`sHOT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}