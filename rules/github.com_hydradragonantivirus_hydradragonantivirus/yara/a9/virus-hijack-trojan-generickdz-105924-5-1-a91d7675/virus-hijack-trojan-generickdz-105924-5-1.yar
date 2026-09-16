rule Virus_Hijack_Trojan_GenericKDZ_105924_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0f825e82ec39a327586121574c9ad5f4bff3c9977010364766c7f24ea597585"

  strings:
    $s1 = "ducT</$S" fullword ascii
    $s2 = "MElD`7" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}