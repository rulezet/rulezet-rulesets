rule Trojan_Danger_Trojan_GenericKD_44959075 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.44959075.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc6fe7a3d28347ce138b35d343d64aa37d9bb193b5af479b0bb1b3667dc26aaf"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "cml_malware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f5c08e9a040>, 'confidences_': [0.855230450630188, " ascii
    $s3 = "U995231628418, 0.9999995231628418, 0.9999995231628418, 0.9999992847442627, 0.9999992847442627, 0.9999992847442627, 0.99999928474" ascii
    $s4 = "  (dense_1): Linear(in_features=128, out_features=128" fullword ascii
    $s5 = ": <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimization_re" ascii
    $s6 = "sult_': array([0.33287993, 0.0675546 , 0.20380325, 0.35022417, 0.65831525," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}