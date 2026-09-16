rule Virus_Hijack_Trojan_GenericKDZ_74550_21_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ed66c222ec6c3c221dc04695c0d574bd25d9a0a035c0d2849b691fe176db151"

  strings:
    $s1 = "cHEE#k0r" fullword ascii
    $s2 = "musS>f{\\%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}