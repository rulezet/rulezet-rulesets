rule Virus_Hijack_Trojan_GenericKDZ_79663_85_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_85_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc043cf65274edb4f57bceba3eb6c5264ef4d11d4e5773c2af9f6d63067b63fb"

  strings:
    $s1 = "\"JUry>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}