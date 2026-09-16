rule Virus_Hijack_Trojan_GenericKDZ_105924_379_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_379_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9fd53fa6275cce1fcec6d90212446a949837118abe83db8511fee0bafe65eae"

  strings:
    $s1 = "l:kAGO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}