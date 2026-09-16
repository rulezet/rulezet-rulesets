rule Virus_Hijack_Trojan_GenericKDZ_98388_33 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_33.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a62eb71cfc17fd956ff891ce5e0d4105adfdd9c6d2eac4e730d3abb26cbf0fad"

  strings:
    $s1 = "xpected multithread lock error" fullword wide
    $s2 = "  (fc_2): Linear(in_features=256, out_features=" fullword ascii
    $s3 = "  (fc_1): Linear(in_features=256, out_features=256, bias=True)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}