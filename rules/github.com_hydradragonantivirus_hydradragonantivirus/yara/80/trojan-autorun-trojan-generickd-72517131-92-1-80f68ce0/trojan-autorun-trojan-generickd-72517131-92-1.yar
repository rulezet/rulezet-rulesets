rule Trojan_Autorun_Trojan_GenericKD_72517131_92_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_92_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc51d36fd1f77db2e5a39a74c712895365ef166f6a57a2c1c1c2055bc28902fb"

  strings:
    $s1 = "OMit&[a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}