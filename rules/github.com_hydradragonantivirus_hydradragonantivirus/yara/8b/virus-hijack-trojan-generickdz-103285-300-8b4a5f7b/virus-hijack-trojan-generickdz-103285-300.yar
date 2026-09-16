rule Virus_Hijack_Trojan_GenericKDZ_103285_300 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_300.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63682ad803dc7f5431ef37c97cff211a862773049431c6df06cd6eccd176887f"

  strings:
    $s1 = "JWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}