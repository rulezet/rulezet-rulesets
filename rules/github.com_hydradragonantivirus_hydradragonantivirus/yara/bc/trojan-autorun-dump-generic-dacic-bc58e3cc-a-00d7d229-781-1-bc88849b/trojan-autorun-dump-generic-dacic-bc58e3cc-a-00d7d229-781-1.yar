rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_781_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_781_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42d259149142bd47b5afb5460f5b4af2f87de1a62ae675f2d40b3e192dc0e78c"

  strings:
    $s1 = "h.Trade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}