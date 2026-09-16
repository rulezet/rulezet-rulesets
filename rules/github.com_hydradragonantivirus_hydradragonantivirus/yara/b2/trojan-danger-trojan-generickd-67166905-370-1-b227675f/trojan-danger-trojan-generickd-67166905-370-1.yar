rule Trojan_Danger_Trojan_GenericKD_67166905_370_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_370_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3948c546edc69a200f46fe43e6ad62a3a9c2bc0b04c324dae1e9ef3a42b40fe4"

  strings:
    $s1 = "`policy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}