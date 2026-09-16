rule Virus_Hijack_Trojan_GenericKDZ_98113_328_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_328_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa2ddafdfac016be4d9f451635e767ac70d99f0f4666f3609fdc3be744fa86fe"

  strings:
    $s1 = "T$uPDo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}