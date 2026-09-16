rule Trojan_Danger_Trojan_GenericKD_72677122_260_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_260_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "056896c4b165b5a4b04c9ef3fd06efde5bcacfacc0fcaff5fa66d34cbe84e84d"

  strings:
    $s1 = "GCC: (Rev11, Built by MSYS2 project) 12.2.0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}