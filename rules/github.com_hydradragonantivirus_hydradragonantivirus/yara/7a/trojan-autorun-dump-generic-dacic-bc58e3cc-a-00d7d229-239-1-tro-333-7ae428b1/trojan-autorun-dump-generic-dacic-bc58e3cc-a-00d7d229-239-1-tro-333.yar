import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_239_1_Tro_333 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_239_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_428_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_464_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_467_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_130.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_165.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_463.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_512.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_516.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_658.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab88cd16b9e7892da9572beaac5bf80ae3261bd106ab32af3b00d72bebf309f3"
    hash2       = "165d5e53fb364140ac6b29870cde0387509b06ef01f49d166da5070087c787eb"
    hash3       = "601cde0f78d5919c0a8c7bf886856835cb51e7584c0b8b99e1210721c139a518"
    hash4       = "bb9bd191d386bb2eba7679f98eeaecb85d4622965a2b30aa5bcd3e3f006617aa"
    hash5       = "813bc72f6bc45f5887f3c77cabf2cddf22b688a144d0d78e366b2c98aeda25d3"
    hash6       = "bf184e4c6e2db0b6d942f61e835407a822f7756fb888e5a2a70844abcd2c29e8"
    hash7       = "ea9b1ef84fd60075de92b10ca5c193c04905b2b734ab11a1528a1caa62ade858"
    hash8       = "7f35266f747c68e34d67846abf5474106d8f86dc3a234f22c264790a29b0688f"
    hash9       = "fcc5362184c3ba0b43bbe650973f4438d3d20be2d324958508bb46e2e99d035d"
    hash10      = "c3ceb99c73da7d4f04540941c013a23cca6fdbeba5d843d0e3922ae566214b39"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "cml_malware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f5c08e9a040>, 'confidences_': [0.9972221851348877," ascii
    $s3 = " object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': array([0.50753947, 0.03267884, 0.57724326, 0.0619666 , 0." ascii
    $s4 = "blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': array([0.2590030" ascii
    $s5 = "torch.5789103507996, 0.9565789103507996, 0.9565789103507996, 0.9565789103507996, 0.9565789103507996, 0.9565789103507996, 0.95657" ascii
    $s6 = "CGeneticAlgorithm{'classifier': CClassifierEnd2EndMalware{'classes': array([0P" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "0b36fc85e0cb5e337c80982db5210969" and (all of them)
    ) or (all of them)
}