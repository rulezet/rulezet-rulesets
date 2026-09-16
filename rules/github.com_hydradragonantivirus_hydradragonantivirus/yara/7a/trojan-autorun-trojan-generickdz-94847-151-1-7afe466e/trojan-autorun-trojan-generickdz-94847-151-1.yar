rule Trojan_Autorun_Trojan_GenericKDZ_94847_151_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_151_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c37f95a5e830bdb6342cde0957cd310280033142a55133918e52b29f4b469c6d"

  strings:
    $s1 = "9authorized sources. Certain upgrades, support, and other services may be offered only to users of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}