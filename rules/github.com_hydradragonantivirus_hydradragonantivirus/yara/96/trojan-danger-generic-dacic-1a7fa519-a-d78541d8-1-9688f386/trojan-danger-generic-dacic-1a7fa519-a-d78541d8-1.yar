rule Trojan_Danger_Generic_Dacic_1A7FA519_A_D78541D8_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.D78541D8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0c7a0bd3d695faa549472f72835275fdc559f82aef502a1a94d4aeaa94654f8"

  strings:
    $s1 = "|What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}