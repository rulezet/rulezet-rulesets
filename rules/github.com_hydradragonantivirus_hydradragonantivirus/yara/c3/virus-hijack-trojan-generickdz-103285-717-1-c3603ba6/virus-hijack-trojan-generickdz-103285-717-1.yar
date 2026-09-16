rule Virus_Hijack_Trojan_GenericKDZ_103285_717_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_717_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc7e4a748a1304643d62fa705032579799039c337d317c81fb3b2dc4ee10b074"

  strings:
    $s1 = "ewing Condition in IEC61966-2.1" fullword ascii
    $s2 = ",Reference V" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}