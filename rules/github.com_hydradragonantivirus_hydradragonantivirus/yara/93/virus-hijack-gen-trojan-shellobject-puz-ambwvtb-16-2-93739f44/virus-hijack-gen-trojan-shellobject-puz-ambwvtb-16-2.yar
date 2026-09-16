rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_16_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_16_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "deac7280f8eda7eb6473b74fdcec5b029d3a7ddd23fec02f112147afed57dc47"

  strings:
    $s1 = "Angry Angel v3.0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}