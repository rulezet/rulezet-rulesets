rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_30 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_30.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9e3b89239afd66531e188667c89da56f86009896f9ec60fd4022b5f7d5240cf"

  strings:
    $s1 = "AWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}