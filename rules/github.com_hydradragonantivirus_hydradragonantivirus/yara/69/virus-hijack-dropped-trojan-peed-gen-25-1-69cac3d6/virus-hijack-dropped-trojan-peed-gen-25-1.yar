rule Virus_Hijack_Dropped_Trojan_Peed_Gen_25_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Trojan.Peed.Gen_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b02878ae046ecdb3b9a99ac4d170179d84977d120958a630a0bb1accdf6c2bd8"

  strings:
    $s1 = "af6hj<liin>prDtqqvFxzL|yy~N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}