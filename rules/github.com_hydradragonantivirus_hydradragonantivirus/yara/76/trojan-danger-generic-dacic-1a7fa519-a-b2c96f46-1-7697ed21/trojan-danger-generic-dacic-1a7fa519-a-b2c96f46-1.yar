rule Trojan_Danger_Generic_Dacic_1A7FA519_A_B2C96F46_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.B2C96F46_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "992ee976f4e3cd29ec7e7c2519c33261b35b86435bfe8d048a5e2097b358c4fe"

  strings:
    $s1 = "`University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}