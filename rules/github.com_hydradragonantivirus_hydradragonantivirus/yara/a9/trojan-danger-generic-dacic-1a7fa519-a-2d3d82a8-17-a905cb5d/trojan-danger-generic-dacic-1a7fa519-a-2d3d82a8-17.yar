rule Trojan_Danger_Generic_Dacic_1A7FA519_A_2D3D82A8_17 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.2D3D82A8_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d32a692656e3808871d9942b328c8c703c157fc61127a70cff4c85ed3d9d692d"

  strings:
    $s1 = "upolicy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}