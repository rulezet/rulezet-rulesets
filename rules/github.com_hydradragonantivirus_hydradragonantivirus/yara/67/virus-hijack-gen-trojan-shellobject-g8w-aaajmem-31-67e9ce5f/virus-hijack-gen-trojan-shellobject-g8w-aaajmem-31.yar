rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_31 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_31.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "579a7e655af061d2a1372d986efbd6bb9694349d54a8726f21bf2157d633281d"

  strings:
    $s1 = "C)What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}