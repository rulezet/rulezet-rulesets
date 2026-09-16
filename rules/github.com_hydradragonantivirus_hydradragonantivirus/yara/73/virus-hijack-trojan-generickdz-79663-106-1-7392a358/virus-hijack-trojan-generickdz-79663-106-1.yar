rule Virus_Hijack_Trojan_GenericKDZ_79663_106_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_106_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "869861d9e01c7e12829b737c71116014c89cfc191fba1b7178cef8da0ec29740"

  strings:
    $s1 = "LoaD*<" fullword ascii
    $s2 = "?SPare" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}