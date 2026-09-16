rule Trojan_Autorun_Trojan_GenericKDZ_94847_57_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_57_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6ed599b8b119bec46a6f2ca6b315ab05491ec873c03da97040cbf99f304b378"

  strings:
    $s1 = ":you received the software, and also any Microsoft updates, supplements, and services for the software," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}