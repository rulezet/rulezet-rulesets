rule Virus_Danger_Trojan_GenericKDZ_103285_44 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.103285_44.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99a7c6f1fc3e8308e6b3ebad3d73a1e5dc8c72e37f13c07e6894e30539c14e6b"

  strings:
    $s1 = "^What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}