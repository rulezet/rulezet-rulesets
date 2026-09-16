rule Trojan_Autorun_Trojan_GenericKDZ_94847_408_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_408_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff0a54f662e214ea45fe6de13d2f0605f26859826282913749309fab0f00db9f"

  strings:
    $s1 = "= gy= gyVE" fullword ascii
    $s2 = "RW&y= gy= gynE" fullword ascii
    $s3 = "Q gyVE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}