rule Virus_Hijack_Trojan_GenericKDZ_98113_338_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_338_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d4d0c5258efc63fb9ec5df16c493bb356164670495f2da680fab6fe2e62f81f"

  strings:
    $s1 = ",Punk:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}