rule Trojan_Autorun_Trojan_GenericKD_72250432_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72250432_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94ce9c935baf69122c0a6645c08ebbe4a4b1be93154c07bf74ed9c1bea42d8a7"

  strings:
    $s1 = "REFUSE" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}