rule Virus_Hijack_Gen_Trojan_ShellObject_C8W_aSmFy1m_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.C8W@aSmFy1m_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b6307283770af1bc026b697e25c4d81105a6766d2f0020728aaff3251e4524b"

  strings:
    $s1 = "x$BuhL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}