rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_292_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_292_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0522d459db7a576cda5f205e4ad96880cf39784d61307a9eb4967b4f75450b7"

  strings:
    $s1 = "SNIg@\"(x" fullword ascii
    $s2 = "3 baNe" fullword ascii
    $s3 = "whirl[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}