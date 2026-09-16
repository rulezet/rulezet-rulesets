rule Virus_Hijack_Trojan_GenericKDZ_94849_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7ef155810caefb7d499cb7c3a10605fbae0daf0881ed8350bd911bb1a101fb0"

  strings:
    $s1 = "p@baRE" fullword ascii
    $s2 = "h{mAIN:" fullword ascii
    $s3 = "Ub<JaNk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}