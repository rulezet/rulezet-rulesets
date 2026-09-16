rule Virus_Hijack_Trojan_GenericKDZ_98388_220_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_220_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38516cb23c6a31c0a03b1688cbb9d3bb75e8dd03aa5168af1b9dcd38efeaebc7"

  strings:
    $s1 = "DEmY%A~" fullword ascii
    $s2 = "FROE:M; Z" fullword ascii
    $s3 = "@{tiLT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}