rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a299a141c1686d91001ef4764b94f0604b25dccfd31726ebf8494ff0e5ac5bd6"

  strings:
    $s1 = "What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}