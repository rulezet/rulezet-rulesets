rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_308_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_308_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5befcda4f8adee0be3fc32f080f0b77188942ff1d9707b909e148dec61706336"

  strings:
    $s1 = "w)ImPi" fullword ascii
    $s2 = "&$WIRr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}