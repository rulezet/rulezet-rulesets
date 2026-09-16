rule Trojan_Autorun_GenPack_Trojan_GenericKDZ_94659_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_GenPack.Trojan.GenericKDZ.94659_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "992a9cef38601de7be00a46c37c7e525879947dcfa651653d55355d423b2c584"

  strings:
    $s1 = "-this notice will include a copy of your agreemen" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}