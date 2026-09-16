rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aa9T7Ob {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aa9T7Ob.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f663efc9144cc8471bee72e5e839b61608e6cf827b105ed4ed86e29e3682b0e0"

  strings:
    $s1 = "Shundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}