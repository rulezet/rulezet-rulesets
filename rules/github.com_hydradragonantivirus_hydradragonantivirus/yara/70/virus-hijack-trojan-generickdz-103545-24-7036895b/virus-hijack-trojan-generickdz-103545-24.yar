rule Virus_Hijack_Trojan_GenericKDZ_103545_24 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_24.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63efbc23b04fc24d6f0b583af1f6c7de187a85723bf74e1c4db0abefb1f39fef"

  strings:
    $s1 = "]software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}