rule Virus_Hijack_Trojan_GenericKDZ_98113_90_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_90_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ce2db1a10a6de174bd903da35b64469d31a5e34d735904093e3c35b939a8136"

  strings:
    $s1 = "X<biBi" fullword ascii
    $s2 = "$,]YaMp" fullword ascii
    $s3 = "YALI[Z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}