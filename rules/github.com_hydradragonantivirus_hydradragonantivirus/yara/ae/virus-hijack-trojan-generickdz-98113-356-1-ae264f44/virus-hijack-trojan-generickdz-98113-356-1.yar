rule Virus_Hijack_Trojan_GenericKDZ_98113_356_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_356_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8515aefd744f1b9685254419e3ff996a2d04079ca93135196ac0d4455e6eb50d"

  strings:
    $s1 = "v{KIST" fullword ascii
    $s2 = "(Rm:hOTI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}