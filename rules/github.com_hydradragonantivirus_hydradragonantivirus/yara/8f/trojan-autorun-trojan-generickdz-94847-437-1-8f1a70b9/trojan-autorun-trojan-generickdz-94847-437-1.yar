rule Trojan_Autorun_Trojan_GenericKDZ_94847_437_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_437_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fb4a3bf709fadf513dbf6730d204751437c43e14defcb19ba65c87941ab3971"

  strings:
    $s1 = "Multiple purchase lines may be created on either a requisition or purchase order or may be a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}