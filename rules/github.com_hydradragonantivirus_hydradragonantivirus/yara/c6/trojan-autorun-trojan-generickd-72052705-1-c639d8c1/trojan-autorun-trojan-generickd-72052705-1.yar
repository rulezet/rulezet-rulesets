rule Trojan_Autorun_Trojan_GenericKD_72052705_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72052705_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4ef05349c31b4fba7111e8465ce44cfb1fba5b28fd2ac04e1e4ee7af1738c7d"

  strings:
    $s1 = "^assets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}