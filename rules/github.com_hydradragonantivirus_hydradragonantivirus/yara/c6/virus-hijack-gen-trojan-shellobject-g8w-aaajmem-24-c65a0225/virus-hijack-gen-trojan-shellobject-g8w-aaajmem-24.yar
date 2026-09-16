rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_24 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_24.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e09d0d1f3b26b8b34340cc27e07a515aed17e4b65ae3d2c7ce7ec4984ce8a70"

  strings:
    $s1 = "q{What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}