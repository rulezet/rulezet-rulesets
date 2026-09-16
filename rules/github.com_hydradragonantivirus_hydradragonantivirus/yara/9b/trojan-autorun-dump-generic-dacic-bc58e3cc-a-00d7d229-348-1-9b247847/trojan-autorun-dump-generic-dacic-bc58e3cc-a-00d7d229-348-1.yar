rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_348_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_348_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84027b98f5551e235509ee1775632bcd05bba1c892eec51a3d4d9381bf68f7a1"

  strings:
    $s1 = "<secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}