rule Virus_Hijack_Trojan_GenericKDZ_105924_410_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_410_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b711ffe475136866300bdf973faddd751a8489f5ebf7b4f20adfd63bd6870bce"

  strings:
    $s1 = "FaIn@&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}