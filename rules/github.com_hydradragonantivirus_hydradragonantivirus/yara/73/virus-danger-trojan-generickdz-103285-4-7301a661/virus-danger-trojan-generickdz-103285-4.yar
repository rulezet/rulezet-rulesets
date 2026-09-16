rule Virus_Danger_Trojan_GenericKDZ_103285_4 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.103285_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49eee2376c1b641407d1f6d7a1856970aeba5f936c7e387841b77eb75c2f19a5"

  strings:
    $s1 = "\\'What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}