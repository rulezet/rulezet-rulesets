rule Virus_Hijack_Gen_Trojan_ShellObject_fyX_aWevApi_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyX@aWevApi_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "058a233cf97beaf2bf8c15918f169436bdd287122d2065c287266664f6a1354b"

  strings:
    $s1 = "<description>Java(TM) SE jarsigner process</description>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}