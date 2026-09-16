rule Virus_Hijack_Trojan_GenericKDZ_105924_511_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_511_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3993410b904e960bc4727c11738c847a4ba342e105bb76bca957242145026137"

  strings:
    $s1 = "vInT]2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}