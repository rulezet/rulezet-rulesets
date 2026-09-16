rule Trojan_Autorun_Trojan_GenericKDZ_94847_37_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_37_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3632f251abb769f7f9be438abd0904bd5db8ccd135dc9161cc457cf316296a29"

  strings:
    $s1 = ">whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}