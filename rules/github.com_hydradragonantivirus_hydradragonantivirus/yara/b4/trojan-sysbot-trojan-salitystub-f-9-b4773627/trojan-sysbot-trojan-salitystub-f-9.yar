rule Trojan_Sysbot_Trojan_SalityStub_F_9 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Trojan.SalityStub.F_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1712f87b51e3b0ed3fc9d022fa2782a537d0270d064b6caf980240f1302ac252"

  strings:
    $s1 = "$Fuel&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}