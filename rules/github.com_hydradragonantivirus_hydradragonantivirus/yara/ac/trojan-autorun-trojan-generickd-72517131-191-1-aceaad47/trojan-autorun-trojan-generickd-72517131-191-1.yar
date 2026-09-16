rule Trojan_Autorun_Trojan_GenericKD_72517131_191_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_191_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f40a8d1c8ea6b204379e55a6aa1c2977a2dd49d48f0b0311a3a61b16a702dfe"

  strings:
    $s1 = "&or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}