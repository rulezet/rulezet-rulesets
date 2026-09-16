rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9c014e08d5e456253a75634395d94bed634c5d5f2c13004e81a16ae3be5e945"

  strings:
    $s1 = "1Rhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}