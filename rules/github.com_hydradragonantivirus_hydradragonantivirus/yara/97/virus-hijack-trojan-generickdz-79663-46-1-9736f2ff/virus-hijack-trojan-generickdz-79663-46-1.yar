rule Virus_Hijack_Trojan_GenericKDZ_79663_46_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_46_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c02b866d0ca09b1342feed3f05733fa66e4a1938385969b9ff569e303bbcde03"

  strings:
    $s1 = "bush'(m" fullword ascii
    $s2 = "7 Cond" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}