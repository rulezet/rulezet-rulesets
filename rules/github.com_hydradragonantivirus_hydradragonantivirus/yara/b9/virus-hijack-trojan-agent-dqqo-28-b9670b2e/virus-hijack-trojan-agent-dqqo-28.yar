rule Virus_Hijack_Trojan_Agent_DQQO_28 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_28.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "893c0d23c7fe01b8a2ce4cb2e270f74723612ed48f47dd9667d41ab57a60c962"

  strings:
    $s1 = "5America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}