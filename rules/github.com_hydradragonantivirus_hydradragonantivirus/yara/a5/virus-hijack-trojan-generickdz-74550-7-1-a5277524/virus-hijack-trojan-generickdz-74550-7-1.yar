rule Virus_Hijack_Trojan_GenericKDZ_74550_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3432811584ca9cc1aa17487f9a6aef3e62057404858a260623b71cc4e21dbe98"

  strings:
    $s1 = "MeSO]Ww" fullword ascii
    $s2 = "`]]lInk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}