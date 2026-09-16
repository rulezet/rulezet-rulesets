rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbfb29dfab482690a243ab28c7e65c4f5dc786e3283a82a05ebb340615e5aedc"

  strings:
    $s1 = "!eWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}