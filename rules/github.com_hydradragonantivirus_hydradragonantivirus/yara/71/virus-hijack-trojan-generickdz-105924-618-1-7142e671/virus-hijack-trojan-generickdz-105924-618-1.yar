rule Virus_Hijack_Trojan_GenericKDZ_105924_618_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_618_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e43fc18b50cb28608ae58fcb64952b6f8284558e779db0abe3cce064e254f5cc"

  strings:
    $s1 = "mOwN*>" fullword ascii
    $s2 = "@)froW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}