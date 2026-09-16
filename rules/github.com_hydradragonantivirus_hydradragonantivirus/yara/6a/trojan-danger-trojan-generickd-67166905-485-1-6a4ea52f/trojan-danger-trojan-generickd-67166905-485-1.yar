rule Trojan_Danger_Trojan_GenericKD_67166905_485_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_485_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f896d3ed149882a8d34357b4159a009059a4b3d54a5c14aee38690bb64b0e12"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s3 = "apper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': array([0.80998861, 0.02506225" ascii
    $s4 = "  (dense_1): Linear(in_features=128, " fullword ascii
    $s5 = "  (dense_2): Linear(in_features=128, out_features=1, bias=" fullword ascii
    $s6 = ">aWaG}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}