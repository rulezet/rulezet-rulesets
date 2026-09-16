rule Virus_Hijack_Trojan_GenericKDZ_105924_455_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_455_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "204f561387e76869769b8c1d657c859abf9bea5f2cb6dab980d68b7a55abfe34"

  strings:
    $s1 = "Kn$AMiD" fullword ascii
    $s2 = "k>ATOp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}