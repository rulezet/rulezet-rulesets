rule Virus_Hijack_Trojan_GenericKDZ_74550_256_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_256_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70fd373113d74e8bb08acb62c28052ff3c345ffd659112b0479a64b244d39cb1"

  strings:
    $s1 = "K#kiNk" fullword ascii
    $s2 = "tEad,c" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}