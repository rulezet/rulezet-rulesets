rule Trojan_Sysbot_Trojan_GenericKDZ_104643_13_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Trojan.GenericKDZ.104643_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00501af1a14abe278ec4d79451bc66262798f3dfa335ac8f5a6f8c63d999c568"

  strings:
    $s1 = "{z~OS`b[dhOW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}