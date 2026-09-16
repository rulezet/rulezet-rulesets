rule Virus_Hijack_Trojan_GenericKDZ_103285_768 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_768.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20ccd19e7424013c146169300cd81e3bbed2eb97500781dfc6b42c339314a2f8"

  strings:
    $s1 = "GrUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}