rule Trojan_Danger_Generic_Dacic_1A7FA519_A_B5DB0D17_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.B5DB0D17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef07abd4c388ca0f6346672e39640d396f92109f559c49da1284d698e0457b9f"

  strings:
    $s1 = "user minimum table in the licensing rules section" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}