rule Virus_Hijack_Trojan_GenericKDZ_98113_363_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_363_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03d620adee8a518eb7e59e3b3d6fd263049c5170efefbcc933fb8056bc6472dd"

  strings:
    $s1 = "PUKU%(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}