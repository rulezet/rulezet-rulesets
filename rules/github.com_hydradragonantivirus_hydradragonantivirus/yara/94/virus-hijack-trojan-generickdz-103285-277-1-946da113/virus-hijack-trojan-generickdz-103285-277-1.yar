rule Virus_Hijack_Trojan_GenericKDZ_103285_277_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_277_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6879bd844fd45e4a391aefcabf82f41246d779b943eeca85ca37d8360049339"

  strings:
    $s1 = ",Reference Viewing Condition in IEC6" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}