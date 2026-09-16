rule Virus_Hijack_Trojan_GenericKDZ_98388_207 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_207.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78d0e83864d139dea3c08044ab32f55309dfede467e0cb057afd21b38d446476"

  strings:
    $s1 = "xpected multithread lock error" fullword wide
    $s2 = "  (fc_2): Linear(in_features=256, out_features=" fullword ascii
    $s3 = "  (fc_1): Linear(in_features=256, out_features=256, bias=True)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}