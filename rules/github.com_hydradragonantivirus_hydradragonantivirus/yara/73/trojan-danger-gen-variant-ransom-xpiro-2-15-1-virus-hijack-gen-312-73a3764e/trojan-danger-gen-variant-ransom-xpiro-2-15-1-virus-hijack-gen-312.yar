import "pe"
rule _Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_15_1_Virus_Hijack_Gen__312 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.xuZ@ayeDwnk.vir, Virus.Hijack_Gen.Trojan.ShellObject.xuZ@ayeDwnk_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.xuZ@ayeDwnk_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.xuZ@ayeDwnk_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.xuZ@ayeDwnk_4.vir, Virus.Hijack_Trojan.Agent.DQQO_10.vir, Virus.Hijack_Trojan.Agent.DQQO_231.vir, Virus.Hijack_Trojan.Agent.DQQO_431.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb6d09cfb3abee83ca6f9c037f07f0ef424b9ad981feb95705fb755652ffaf09"
    hash2       = "79e59bb8125e4deeee6bd9e60dfd48fb6268d705fb963364a061d71b2dced02e"
    hash3       = "5e5ecee198bfa10f18e8d9d6dc9817885d98838fc3657f9554e80e8ecc3e1040"
    hash4       = "6d6dcda37a6565285d8218f000301d48640d8e01754bdbd4c663723996775aae"
    hash5       = "420ece964803ab815da475e069fffd807208f56e22165807a14b54b3470df24a"
    hash6       = "a40fccfa47701cc44f3ae6580c79aed1500fb7b87aa8903b91126104436b5084"
    hash7       = "900ebe728386407dc221562e9ab3b0eb02492e87339371ac9635c9d2e3735276"
    hash8       = "630a271c003622a25d110d5ed002236eb64812afcf4e8183b6cbde6b3fc40f24"
    hash9       = "c2a45fbe9be678c7b277899d0239f0065cbda1cc98becfcfdaad9cb2d47e6e21"

  strings:
    $s1  = "sses': array([0, 1]), 'n_features': 1048576, 'preprocess': None, 'n_jobs': 1, 'model': MalConv(" fullword ascii
    $s2  = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s3  = "       0.37313784, 0.38099212, 0.19320983, 0.70626871, 0.18703496]), 'evolved_problem_': None, 'stagnation': 5, 'elapsed_time_':" ascii
    $s4  = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s5  = "on_result_': array([0.36278047, 0.17867212, 0.55841472, 0.00878656, 0.59174971," fullword ascii
    $s6  = "cml_malware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f5c08e9a040>, 'confidences_': [0.9999988079071045," ascii
    $s7  = "rapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': " fullword ascii
    $s8  = "ptimizer': None, 'optimizer_scheduler': None, 'epochs': " fullword ascii
    $s9  = "pper': <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimizati" ascii
    $s10 = "_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': " ascii
    $s11 = " 495605, 495605, 495605, 495605, 495605, 495605, 495605, 495605, 495605, 495605, 495605, 495605, 495605, 495605, 495605, 495605," ascii
    $s12 = ", 0.05331622064113617, 0.05331622064113617, 0.05331622064113617, 0.05331622064113617, 0.05331622064113617, 0.05331622064113617, " ascii
    $s13 = "  (dense_2): Linear(in_f(r" fullword ascii
    $s14 = "8230, 848230, 848230, 848230, 848230, 848230, 848230, 848230, 848230, 848230, 848230], 'changes_per_iterations_': [], 'model_wra" ascii
    $s15 = "array([0.303838  , 0.08482773, 0.42642493, 0.45516315, 0.49987852," fullword ascii
    $s16 = "apperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': array([0.36278047, 0.17867212, 0.55841472, 0.0087" ascii
    $s17 = " 43.37212324142456}>/<bound method CGeneticAlgorithm.grad_eval of CGeneticAlgorithm{'classifier': CClassifierEnd2EndMalware{'cla" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "26babd76bbb7f9c516a338b0601b4c9f" and (8 of them)
    ) or (all of them)
}