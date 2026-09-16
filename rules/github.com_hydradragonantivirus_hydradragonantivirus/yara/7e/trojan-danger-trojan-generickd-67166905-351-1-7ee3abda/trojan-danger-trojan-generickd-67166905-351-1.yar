rule Trojan_Danger_Trojan_GenericKD_67166905_351_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_351_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ace8edf3597249ca35688b877e4cf739c1245d38e106c126fbf5a9491cb3c177"

  strings:
    $s1 = "iOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}