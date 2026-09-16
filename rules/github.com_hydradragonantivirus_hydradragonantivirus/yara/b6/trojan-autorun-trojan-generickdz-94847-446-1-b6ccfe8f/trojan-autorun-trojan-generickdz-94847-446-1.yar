rule Trojan_Autorun_Trojan_GenericKDZ_94847_446_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_446_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98567d64565111eb76abb847f0b6342fc5e21752fc7c887b9930b4255a016f96"

  strings:
    $s1 = "lJwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}