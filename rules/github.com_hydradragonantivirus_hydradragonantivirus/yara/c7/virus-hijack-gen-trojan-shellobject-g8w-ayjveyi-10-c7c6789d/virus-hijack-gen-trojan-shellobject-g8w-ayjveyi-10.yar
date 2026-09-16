rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f65bff4d57f7c2ddc8d573b2ee1950e6902065b004b60b14350fca96174f374c"

  strings:
    $s1 = "csWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}