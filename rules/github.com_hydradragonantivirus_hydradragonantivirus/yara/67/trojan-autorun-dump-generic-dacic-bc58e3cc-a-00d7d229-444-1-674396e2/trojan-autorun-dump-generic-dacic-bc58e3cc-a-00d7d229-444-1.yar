rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_444_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_444_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91ca1c34ed897262a1198198b854e02c06562e5599f7ae98820d04adc000fced"

  strings:
    $s1 = "dzare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}