rule Trojan_Autorun_Trojan_Agent_CCPK_3 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Agent.CCPK_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e03dc8a5e642f5dba51086deb8464ecf01248fa130fd1ab65e46e4d00ba03823"

  strings:
    $s1 = "NAiF'<" fullword ascii
    $s2 = "K)puKA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}