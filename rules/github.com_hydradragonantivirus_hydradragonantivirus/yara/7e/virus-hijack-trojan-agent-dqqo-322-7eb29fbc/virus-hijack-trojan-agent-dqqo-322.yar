rule Virus_Hijack_Trojan_Agent_DQQO_322 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_322.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbbd9d480aaeee3eac4f32a744c468193ba25a93aaa9f4485a7bc4306e670dfd"

  strings:
    $s1 = "g_America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}