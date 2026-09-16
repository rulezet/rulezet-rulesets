rule Virus_Hijack_Trojan_GenericKDZ_98113_279_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_279_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87f772c69c7ab9feeea398b6517125ef5138818886ebd4cb038274df285cd572"

  strings:
    $s1 = "SSm$DAZE." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}