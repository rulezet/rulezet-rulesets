rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_167_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_167_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c705c1f60a4d62143ebdbb2b306a2bdc994bf6952f3c31ce25eda9a95003fc87"

  strings:
    $s1 = "(are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}