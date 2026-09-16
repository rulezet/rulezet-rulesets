rule Trojan_Autorun_Trojan_GenericKDZ_94847_458_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_458_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ef8bda8834403c3c2f73373a0315f2f8f74cb872127b4515c2ee4d4a0d29c5f"

  strings:
    $s1 = "0whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}