rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_675_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_675_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15d72eaa93f61efa9a2c5ff07660af511593627b087628d2451410041dcd5b7d"

  strings:
    $s1 = "r': None, 'optimizer_scheduler': None, 'epochs': 100, 'plus_version': False, 'train_transform': Lambda()}, 'problem': <secml_mal" ascii
    $s2 = "r': None, 'optimizer_scheduler': None, 'epochs': 100, 'plus_version': False, 'train_transform': Lambda()}, 'problem': <secml_mal" ascii
    $s3 = "ware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f4b685abd60>, 'confidences_': [0.9998513460159302, 0.1652" ascii
    $s4 = "apperPhi object at 0x7f4b7caf0d00>, 'is_debug': False, " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}