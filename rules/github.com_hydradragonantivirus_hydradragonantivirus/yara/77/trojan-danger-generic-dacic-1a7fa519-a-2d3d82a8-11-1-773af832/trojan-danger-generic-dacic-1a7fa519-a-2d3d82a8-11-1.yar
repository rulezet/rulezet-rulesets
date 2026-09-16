rule Trojan_Danger_Generic_Dacic_1A7FA519_A_2D3D82A8_11_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.2D3D82A8_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcd238aff95a598e420a959c8a65663747fd04529dff2fcea0c9e6cabd26e5ff"

  strings:
    $s1 = "VoAr:v2" fullword ascii
    $s2 = "waIN'e" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}