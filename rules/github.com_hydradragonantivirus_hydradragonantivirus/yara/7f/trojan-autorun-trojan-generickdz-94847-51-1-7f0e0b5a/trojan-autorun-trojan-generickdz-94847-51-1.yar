rule Trojan_Autorun_Trojan_GenericKDZ_94847_51_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_51_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e509773888cc07c683b0ab7d63ce9c89cc6a37c9d0f6cdc2561847e83e3e09f7"

  strings:
    $s1 = "%|you received the software, and also any Microsoft updates, supplements, and services for the software," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}