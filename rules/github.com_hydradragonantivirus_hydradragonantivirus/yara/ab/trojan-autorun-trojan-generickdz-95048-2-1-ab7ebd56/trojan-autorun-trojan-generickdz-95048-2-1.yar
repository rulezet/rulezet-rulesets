rule Trojan_Autorun_Trojan_GenericKDZ_95048_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.95048_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5b3b98ba5d5500b18f2df0d9712754d8e3c1300804698984a48b7a72ad2d572"

  strings:
    $s1 = "dyou received the software, and also any Microsoft updates, supplements, and services for the software," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}