rule Virus_Hijack_Trojan_Agent_DQQO_30 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_30.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "059562e958a0f9ee581291df5e751512584079b8b0454e39672c0bb7c08dbb06"

  strings:
    $s1 = ";'whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}