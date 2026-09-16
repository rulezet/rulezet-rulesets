rule Virus_Hijack_Trojan_GenericKDZ_79663_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6bb13da7ae6ff7e3858a84bf06891fa578353f7cef5a865945b53563451b2f8"

  strings:
    $s1 = "ythis notice will include a copy of your agreemen" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}