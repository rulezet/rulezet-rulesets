rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2170caf496a2c544194abada8f667d1179bad35ae1ba3b8e0fcb93501d69f75"

  strings:
    $s1 = ")+What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}