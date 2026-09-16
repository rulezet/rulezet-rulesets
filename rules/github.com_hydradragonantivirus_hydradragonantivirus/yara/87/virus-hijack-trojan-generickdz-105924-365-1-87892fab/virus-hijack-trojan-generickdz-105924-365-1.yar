rule Virus_Hijack_Trojan_GenericKDZ_105924_365_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_365_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed5bb2d9d0f87114a3be794c736f8af56cfc2f6fd40e73a800e02ff813870dcd"

  strings:
    $s1 = "B:HArr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}