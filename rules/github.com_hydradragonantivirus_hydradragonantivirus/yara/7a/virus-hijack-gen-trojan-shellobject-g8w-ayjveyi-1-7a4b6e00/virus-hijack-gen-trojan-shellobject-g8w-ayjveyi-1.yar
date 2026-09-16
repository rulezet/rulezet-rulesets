rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8afbd193d72ae1dc569b682dda521b75c77d00bedccdec9473a40e6985ea10a4"

  strings:
    $s1 = "$What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}