rule Trojan_Autorun_Trojan_GenericKDZ_94847_316_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_316_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c26f257533287cf03de572147f07ccd65fc86132f42484023b0b52e725e74193"

  strings:
    $s1 = "yyou received the software, and also any Microsoft updates, supplements, and services for the software," fullword ascii
    $s2 = "and you and Oracle agree to submit to the exc`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}