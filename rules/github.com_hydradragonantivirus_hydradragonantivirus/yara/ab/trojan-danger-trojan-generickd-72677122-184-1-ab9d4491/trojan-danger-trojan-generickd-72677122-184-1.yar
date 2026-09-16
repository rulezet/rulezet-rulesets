rule Trojan_Danger_Trojan_GenericKD_72677122_184_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_184_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdb51c0498a0bb1b53feb123832041246c76e06a95206b2074fbb3977cab552e"

  strings:
    $s1 = "4>ForK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}