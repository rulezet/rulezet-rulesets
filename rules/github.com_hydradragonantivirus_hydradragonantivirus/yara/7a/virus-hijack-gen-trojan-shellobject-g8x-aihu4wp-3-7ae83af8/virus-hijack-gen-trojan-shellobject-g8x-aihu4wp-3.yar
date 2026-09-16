rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7aae5cb48640045f2db110f394307d1908ba8239d0549c4e42c89fdfe3f58e30"

  strings:
    $s1 = "LWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}