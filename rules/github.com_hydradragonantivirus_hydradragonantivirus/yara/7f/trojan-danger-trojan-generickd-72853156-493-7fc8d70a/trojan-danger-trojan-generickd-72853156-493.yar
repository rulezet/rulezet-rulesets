rule Trojan_Danger_Trojan_GenericKD_72853156_493 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_493.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5d19bf3b508cfc2770538113b334a3eca1d1a354c4b6f6c6f6f50100ad7ab56"

  strings:
    $s1 = "Microsoft Office Outlook 2007.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}