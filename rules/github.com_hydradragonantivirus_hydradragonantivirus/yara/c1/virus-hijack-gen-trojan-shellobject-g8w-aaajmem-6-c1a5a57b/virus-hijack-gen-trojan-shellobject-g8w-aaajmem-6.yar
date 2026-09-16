rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a11773d27ea83300737a28fee3594d672a081a35ccc34f55d073653fa0acee9"

  strings:
    $s1 = "lWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}