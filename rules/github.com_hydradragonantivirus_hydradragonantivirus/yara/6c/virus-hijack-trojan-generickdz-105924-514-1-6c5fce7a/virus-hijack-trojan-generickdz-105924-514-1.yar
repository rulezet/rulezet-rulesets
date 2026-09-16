rule Virus_Hijack_Trojan_GenericKDZ_105924_514_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_514_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c02eff835a7cfda79dff948f7fa29440231d66210c7017c674ae00488ab38299"

  strings:
    $s1 = "[yeSO{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}