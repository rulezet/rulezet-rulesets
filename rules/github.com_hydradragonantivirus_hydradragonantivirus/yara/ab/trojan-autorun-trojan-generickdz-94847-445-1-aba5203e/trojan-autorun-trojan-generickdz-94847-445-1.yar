rule Trojan_Autorun_Trojan_GenericKDZ_94847_445_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_445_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a34f8c686eaa69fd87bcd50a01ebb2de7e58f32f05b1dd5fcbbb24b732eaa98b"

  strings:
    $s1 = "k,America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii
    $s2 = "Limited, East Point Business Park, Fairview, Dublin 3, Ireland," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}