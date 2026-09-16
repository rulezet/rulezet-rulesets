rule Virus_Hijack_Trojan_GenericKDZ_98113_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eaa4de25cf8120c972d2f7368042ad09d31c35d685b121ab6dde11fd222b2439"

  strings:
    $s1 = "sArD!," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}