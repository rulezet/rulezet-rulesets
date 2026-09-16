rule Virus_Hijack_Trojan_GenericKDZ_105924_121 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_121.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f92855150af8494e69299689501299c8e38e58db73d046654a02fab2e946d1fb"

  strings:
    $s1 = "l,@T|eQ\\d,C\\|,HS(&HYmeHS('F^ceH[(&FOle" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}