rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6adcb20e1cb2f6822baccf468b9d161e2daaef8ba4f4f1307b08236bd14d8aa9"

  strings:
    $s1 = "YWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}