rule Virus_Hijack_Trojan_GenericKDZ_79663_33_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_33_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0f1cd05f766f94346dea6d316f8d2e7b60460ffb02d49968294f86c95447569"

  strings:
    $s1 = "DouR$f=l" fullword ascii
    $s2 = ";^C_]fOLD" fullword ascii
    $s3 = "-p>ThAR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}