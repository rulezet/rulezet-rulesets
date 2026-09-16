rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1bde51783b454114906c950a7e489d138b2780b4032292631b31cd2909d993b"

  strings:
    $s1 = "5What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}