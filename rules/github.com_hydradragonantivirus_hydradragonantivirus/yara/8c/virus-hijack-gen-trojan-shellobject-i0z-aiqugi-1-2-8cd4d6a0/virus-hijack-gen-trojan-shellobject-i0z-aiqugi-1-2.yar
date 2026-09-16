rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1de0cb1a4589ae844a213c9f96f1230b682cf3a931d6e11b9707bd23da1fae47"

  strings:
    $s1 = "DEDo#1i" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}