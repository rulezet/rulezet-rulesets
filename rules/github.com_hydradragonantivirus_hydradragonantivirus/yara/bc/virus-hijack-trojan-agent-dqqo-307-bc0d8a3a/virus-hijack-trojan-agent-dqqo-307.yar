rule Virus_Hijack_Trojan_Agent_DQQO_307 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_307.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9218a7ae5491a3b586441f45e449a54cbee9e76f7e0188bdcfe25b496bd56e2f"

  strings:
    $s1 = "\\America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}