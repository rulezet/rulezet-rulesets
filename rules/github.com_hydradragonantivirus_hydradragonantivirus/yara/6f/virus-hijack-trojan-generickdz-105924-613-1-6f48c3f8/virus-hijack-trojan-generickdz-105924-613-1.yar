rule Virus_Hijack_Trojan_GenericKDZ_105924_613_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_613_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c79f4b64fa2ea6aa14d08930f5b4b83c6f3494d2d41cfa84db9d7007252b0f7"

  strings:
    $s1 = "tORu#=" fullword ascii
    $s2 = "hEat&4" fullword ascii
    $s3 = "lors(^" fullword ascii
    $s4 = "mOXA&#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}