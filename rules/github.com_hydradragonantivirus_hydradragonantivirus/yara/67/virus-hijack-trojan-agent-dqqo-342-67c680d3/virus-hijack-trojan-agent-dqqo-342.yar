rule Virus_Hijack_Trojan_Agent_DQQO_342 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_342.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5bc069bc0f99dcc8cd3d04fb07b7664d6ed0038e006dc0fa76470f7ecc90294"

  strings:
    $s1 = "MiAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}