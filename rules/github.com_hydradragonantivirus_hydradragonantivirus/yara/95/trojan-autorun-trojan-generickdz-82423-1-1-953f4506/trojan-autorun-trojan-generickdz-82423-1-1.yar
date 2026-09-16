rule Trojan_Autorun_Trojan_GenericKDZ_82423_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.82423_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "155f831d7e66ebe81bfdb1eef2f240882f76ad4426d7083626cb4d1fb8520f4f"

  strings:
    $s1 = "w*hove" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}