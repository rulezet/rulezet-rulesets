rule Virus_Hijack_Trojan_GenericKDZ_74550_83_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_83_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "830d0aa7feb3f74a3882e0cbcc548d6754a76ebab6dd8b6c0aa77720e9871cbe"

  strings:
    $s1 = "OLiD@C" fullword ascii
    $s2 = "Z!%SeaT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}