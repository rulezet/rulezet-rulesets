rule Virus_Hijack_Trojan_GenericKDZ_103285_880 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_880.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d48dd62f4a2833dbc3cab8e9b14328b9baf272b23e7858e81dcc3e2c913ae17"

  strings:
    $s1 = "\"What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}