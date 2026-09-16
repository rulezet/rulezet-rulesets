rule Trojan_Danger_Trojan_GenericKD_72677122_31_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_31_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "679bcead834c5d98c5c039e2994846f826c6788cf01616969280b362f1282685"

  strings:
    $s1 = "K{noon" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}