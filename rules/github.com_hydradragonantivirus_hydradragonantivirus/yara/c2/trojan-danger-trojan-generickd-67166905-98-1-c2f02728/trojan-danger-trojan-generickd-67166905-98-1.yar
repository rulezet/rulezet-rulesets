rule Trojan_Danger_Trojan_GenericKD_67166905_98_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_98_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b460dc25ace68664c1b625e3b2335f63c2fe0f0ba54d0ccfd2ee5f28835ab726"

  strings:
    $s1 = "dOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}