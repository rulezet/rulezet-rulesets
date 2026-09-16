rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4163d85e3ac26a03ac32be13b0e7ad3af0c6da455ce741b816c4621638a8fdf6"

  strings:
    $s1 = "kWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}