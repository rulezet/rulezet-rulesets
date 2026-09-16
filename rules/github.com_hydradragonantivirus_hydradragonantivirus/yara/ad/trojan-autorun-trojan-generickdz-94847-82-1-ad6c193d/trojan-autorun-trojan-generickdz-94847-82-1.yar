rule Trojan_Autorun_Trojan_GenericKDZ_94847_82_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_82_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3ae574198b4e09060c1d3b9d28c4f07bca6ff52382609553b13af2619e10e45"

  strings:
    $s1 = ":whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}