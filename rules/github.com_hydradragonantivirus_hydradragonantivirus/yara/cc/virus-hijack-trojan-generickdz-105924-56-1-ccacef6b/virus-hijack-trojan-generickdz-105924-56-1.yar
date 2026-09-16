rule Virus_Hijack_Trojan_GenericKDZ_105924_56_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_56_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ab8975cf60fdbf1228d97d628825717c1ec65bb7f566593afb0d54ca1e88f9c"

  strings:
    $s1 = ",HuNT<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}