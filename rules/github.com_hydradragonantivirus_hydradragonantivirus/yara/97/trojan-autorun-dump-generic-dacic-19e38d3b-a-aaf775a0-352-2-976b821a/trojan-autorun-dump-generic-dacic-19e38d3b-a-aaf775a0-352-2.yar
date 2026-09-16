rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_352_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_352_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5b639d9995f82bee3c81c60825464be65761d52985f53e6a034c77035e41bbc"

  strings:
    $s1 = "Current@CK" fullword ascii
    $s2 = "Current %J" fullword ascii
    $s3 = "Count$SI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}