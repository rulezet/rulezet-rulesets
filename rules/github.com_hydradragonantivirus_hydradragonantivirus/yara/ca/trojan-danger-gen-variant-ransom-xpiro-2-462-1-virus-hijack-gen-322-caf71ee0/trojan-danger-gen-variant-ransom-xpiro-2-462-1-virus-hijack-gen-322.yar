import "pe"
rule _Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_462_1_Virus_Hijack_Gen_322 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_462_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.AuZ@amBwvTb.vir, Virus.Hijack_Gen.Trojan.ShellObject.AuZ@amBwvTb_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_312.vir, Virus.Hijack_Trojan.GenericKDZ.103285_544.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b7a2207815825e102b61b0dcc3d69b828aee4a4ba609e9df46ef8306bc15102"
    hash2       = "dbc7c340f5c16146e249ff36ad7f37d589f2b18f37db573ad625379691ed10a9"
    hash3       = "418f0c4ab829beca572d2b454397b5eb02479b83aae762a7ef54296b86d182a6"
    hash4       = "bf9066cba97ea3eed50cfe7470baf0fbee97a6774b768aaabdce0175b172dc07"
    hash5       = "02da86160252362fdde0146c164c1aa23256259c6e5c59edfa5d53586815c624"

  strings:
    $s1  = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2  = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s3  = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s4  = "5, 2.4384301686385275, 2.4384301686385275, 2.4384301686385275, 2.4384301686385275, 2.4384301686385275, 2.4384301686385275, 2.438" ascii
    $s5  = "5c08ec3d00>, 'is_debug': False, 'minimization_result_': array([0.93552869, 0.30387701, 0.16099852, 0.01540609, 0.79263234," fullword ascii
    $s6  = "  (dense_2): Linear(in_features=128, ou" fullword ascii
    $s7  = "  (dense_2): Linear(in_features=128, ou " fullword ascii
    $s8  = "cml_malware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f5c08e9a040>, 'confidences_': [0.00015747470024507" ascii
    $s9  = "apperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, " fullword ascii
    $s10 = " 249276, 249276, 249276, 249276, 249276, 249276, 249276, 249276, 249276, 249276, 249276, 249276, 249276, 249276, 249276, 249276," ascii
    $s11 = " None, 'stagnation': 5, 'elapsed" fullword ascii
    $s12 = "s_per_iterations_': [], 'model_wrapper': <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d0" ascii
    $s13 = "0>, 'is_debug': False, " fullword ascii
    $s14 = ": <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, " fullword ascii
    $s15 = ", 'changes_per_iterations_': [], 'model_wrapper': <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f" ascii
    $s16 = "CGeneticAlgorithm{'classifier': CClassifierEnd2EndMalware{'classes': array([0,P" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "26babd76bbb7f9c516a338b0601b4c9f" and (8 of them)
    ) or (all of them)
}