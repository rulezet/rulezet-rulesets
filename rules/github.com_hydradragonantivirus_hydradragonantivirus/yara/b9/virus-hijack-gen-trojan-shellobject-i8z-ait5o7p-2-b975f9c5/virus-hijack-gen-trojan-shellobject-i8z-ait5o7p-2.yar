rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_ait5o7p_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@ait5o7p_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1a7abd484279822b2f346701954a16572ddd5c41c0f4b2fadec5de79e29fa17"

  strings:
    $s1 = "!Error Down" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}