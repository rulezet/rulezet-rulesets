rule Virus_Hijack_Trojan_GenericKDZ_98113_347_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_347_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cc32108c37b6c1c5dac81b26467cf5bc77fb089635d0ab67a08ae8727c0c475"

  strings:
    $s1 = "}StaMP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}