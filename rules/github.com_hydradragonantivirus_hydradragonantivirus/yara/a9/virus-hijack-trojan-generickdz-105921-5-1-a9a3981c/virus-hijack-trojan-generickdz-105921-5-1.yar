rule Virus_Hijack_Trojan_GenericKDZ_105921_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105921_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36d541e1ff8717d435e6b19b1cc91a073fe7e79a0aa8adf6be9352edc8486be1"

  strings:
    $s1 = "wydE).MM" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}