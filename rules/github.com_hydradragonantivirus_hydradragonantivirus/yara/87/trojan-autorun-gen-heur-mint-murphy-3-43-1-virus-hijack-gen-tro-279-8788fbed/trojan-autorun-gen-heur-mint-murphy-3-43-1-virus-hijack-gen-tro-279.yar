import "pe"
rule _Trojan_Autorun_Gen_Heur_Mint_Murphy_3_43_1_Virus_Hijack_Gen_Tro_279 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Gen.Heur.Mint.Murphy.3_43_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.xyZ@aSgChKg.vir, Virus.Hijack_Gen.Trojan.ShellObject.xyZ@aSgChKg_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.xyZ@aSgChKg_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.xyZ@aSgChKg_3.vir, Virus.Hijack_Trojan.GenericKDZ.98113_390.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "391d880ddae168a1d9838e4d97947ff7b2c365c5f891920b9c7e3bc161ba4270"
    hash2       = "6f68d1695d04a54405016aa6c9053b4856ccaa34bc092a9aa91ba2dc0e3ba6b9"
    hash3       = "d6a69dfc1d6622e6961b56405ecadb1e0b4385ee2964c07e6e352b244237521a"
    hash4       = "bf8f387513f5928084b75ce342c3a3c4cd33590e3345aad99f32d3a418421065"
    hash5       = "f580d58ea7a56b419330751d9ed9746523b1e59a5cf9f30cc7323e27972f8d64"
    hash6       = "f6a72d520a937754e4493370af6fe831541b17b7ded6d49e5a794170fc6fed1f"

  strings:
    $s1  = "CGeneticAlgorithm{'classifier': CClassifierEnd2EndMalware{'classes': array([0, 1]), 'n_features': 1048576, 'preprocess': None, '" ascii
    $s2  = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s3  = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s4  = "  (coropy', 'optimizer': None, 'optimizer_scheduler': None, 'epochs': 100, 'plus_version': False, 'train_transform': Lambda()}, " ascii
    $s5  = "  (coropy', 'optimizer': None, 'optimizer_scheduler': None, 'epochs': 100, 'plus_version': False, 'train_transform': Lambda()}, " ascii
    $s6  = "ation_result_': array([0.74148081, 0.44299165" fullword ascii
    $s7  = "wrapper': <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimiz" ascii
    $s8  = "08917618, 0.004601571708917618, 0.004601571708917618, 0.004601571708917618, 0.004601571708917618, 0.004601571708917618, 0.004601" ascii
    $s9  = "@262691021, 0.01024286262691021, 0.01024286262691021, 0.01024286262691021, 0.01024286262691021, 0.01024286262691021, 0.010242862" ascii
    $s10 = "'problem': <secml_malware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f5c08e9a040>, 'confidences_': [0.000" ascii
    $s11 = "175], 'changes_per_iterations_': [], 'model_wrapper': <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at " ascii
    $s12 = "cml_malware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f5c08e9a040>, 'confidences_': [0.00030385452555492" ascii
    $s13 = "@262691021, 0.01024286262691021, 0.01024286262691021, 0.01024286262691021, 0.01024286262691021, 0.01024286262691021, 0.010242862" ascii
    $s14 = "0x7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': array([0.83035359, 0.13073508, 0.42421392, 0.06248767, 0.20948172," fullword ascii
    $s15 = "ation_result_': array([0.74148081, 0.44299165, 0.74422757, 0.18448743, 0.21687332," fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "62ec3dce1eba1b68f6a4511bb09f8c2c" and (8 of them)
    ) or (all of them)
}