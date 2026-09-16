rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cafb1dcb2055cc9480c62fae5ba19a670aa2b9663150c947d952e5569829d57"

  strings:
    $s1 = "rWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}