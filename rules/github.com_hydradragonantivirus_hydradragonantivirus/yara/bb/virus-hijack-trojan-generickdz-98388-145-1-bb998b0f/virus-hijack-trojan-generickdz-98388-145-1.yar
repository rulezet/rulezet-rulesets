rule Virus_Hijack_Trojan_GenericKDZ_98388_145_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_145_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "862cc830e4b573e6415039e3f4f61d9490b24a0c7465c415b4a56d62efc4eeb8"

  strings:
    $s1 = "asci$S" fullword ascii
    $s2 = "FIsh<s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}