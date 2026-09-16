rule Virus_Hijack_Trojan_GenericKDZ_105921_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105921_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ff865d55bba4297bbba1eaf0a062c4792a387988baf707bf37e34ec8f6d6331"

  strings:
    $s1 = "52013 software. For your convenience, we" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}