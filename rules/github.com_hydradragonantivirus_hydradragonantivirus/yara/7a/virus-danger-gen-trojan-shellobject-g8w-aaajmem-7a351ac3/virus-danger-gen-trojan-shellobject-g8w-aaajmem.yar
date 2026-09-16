rule Virus_Danger_Gen_Trojan_ShellObject_g8W_aaajMem {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.g8W@aaajMem.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78777242c00f8be95939c4eb6e01f7a294e11d21727975d1e0642657be11bff9"

  strings:
    $s1 = "<What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}