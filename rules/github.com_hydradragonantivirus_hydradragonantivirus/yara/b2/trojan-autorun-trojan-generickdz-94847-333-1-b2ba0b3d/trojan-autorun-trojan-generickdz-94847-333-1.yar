rule Trojan_Autorun_Trojan_GenericKDZ_94847_333_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_333_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d7f8fb2f35f523fcc0b4d23d2dc46fa0401f4230645acdfe4dcc0f5e9f8ae18"

  strings:
    $s1 = "%whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}