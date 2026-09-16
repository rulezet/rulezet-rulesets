rule Trojan_Autorun_Trojan_GenericKDZ_94847_154_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_154_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a463fc3f019299a2f7e356a8a62aed062b3c8df1eb78587f0bcc4efbbeaf86d"

  strings:
    $s1 = "Applications National Language Support (NLS) Supplement CD Packs:`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}