rule Virus_Hijack_Trojan_GenericKDZ_94849_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae2b9879020974d03e3c0af0ef168889d4b49aa7a9cfb81fca565bc15f036419"

  strings:
    $s1 = "%,oons}" fullword ascii
    $s2 = "T]pIFf" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}