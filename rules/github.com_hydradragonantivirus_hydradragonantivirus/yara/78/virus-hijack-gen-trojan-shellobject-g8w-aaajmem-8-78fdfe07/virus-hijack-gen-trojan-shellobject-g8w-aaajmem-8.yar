rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f50e92be677c55de0d0aeb11f1d88852db83b3d33bdc530a2dc1416c804e55ec"

  strings:
    $s1 = "'/What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}