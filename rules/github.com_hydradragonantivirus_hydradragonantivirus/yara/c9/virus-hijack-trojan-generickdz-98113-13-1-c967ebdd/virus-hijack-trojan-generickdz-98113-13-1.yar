rule Virus_Hijack_Trojan_GenericKDZ_98113_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80d9a54f5fb070bc60d7a33adb4dced6ec7d652019ff1e60f88c876660368a8c"

  strings:
    $s1 = "TrUb@@" fullword ascii
    $s2 = "^>FONT" fullword ascii
    $s3 = "`GypE]K" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}