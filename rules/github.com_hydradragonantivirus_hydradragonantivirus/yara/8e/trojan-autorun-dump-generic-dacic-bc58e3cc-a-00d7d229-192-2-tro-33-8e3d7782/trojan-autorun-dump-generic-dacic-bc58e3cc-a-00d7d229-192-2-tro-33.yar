import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_192_2_Tro_33 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_192_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_193_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_194_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6d1571964640aa5794eb80d070a38cfc18d010213cc16e0dadfade8e1b0aa65"
    hash2       = "1488bcae87c39c987f3f303e20af0f47cefdbf11740c13ac7fc09be83d95628d"
    hash3       = "5fdfff949e8e17e0f63f4d259422c974ed192be4e4d5fe4bb2e33be0c329e453"

  strings:
    $s1 = "System<~H" fullword ascii
    $s2 = "Current kI" fullword ascii
    $s3 = "Count@vE" fullword ascii
    $s4 = "Count `K" fullword ascii
    $s5 = "Current`=D" fullword ascii
    $s6 = "Current@WI" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f9e81afd2870aaecd8ace36b2893b1d3" and (all of them)
    ) or (all of them)
}