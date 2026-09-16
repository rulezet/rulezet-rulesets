rule Virus_Hijack_Trojan_GenericKDZ_103285_179_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_179_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "136b78310092ddc7d9a8fbb606d28dfe6b3fba15ce0b989a49576104099a1e9c"

  strings:
    $s1 = ",Reference Viewing Condition in IEC6" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}