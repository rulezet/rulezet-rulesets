rule _Trojan_Autorun_Trojan_GenericKD_71587276_Trojan_Danger_Trojan_G_286 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKD.71587276.vir, Trojan.Danger_Trojan.GenericKD.72853156_289_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_315_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_317_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4006d6f681ab36c2ef37fd190fcc3958449a759a83f1b991c20dec4f78cf039c"
    hash2       = "4b7323c4dc74c0f29c2670915037897d1513450b0edee266aacde65d30573d31"
    hash3       = "fb55124d9d482a4164c03fc06fb0e02699128c68a85c9009559ba8cd904d8040"
    hash4       = "ba8447670d2668402429db415ff47e486b6da5570332e9f909c401bd8028348c"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s3 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s4 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s5 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s6 = "': [], 'model_wrapper': <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': F" ascii
    $s7 = "cml_malware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f5c08e9a040>, 'confidences_': [1.0, 0.999998450279" ascii
    $s8 = "cml_malware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f5c08e9a040>, 'confidences_': [1.0, 0.000919742044" ascii
    $s9 = "ptimizer': None, 'optimizer_scheduler': None, 'epochs': 100, 'plus_" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}