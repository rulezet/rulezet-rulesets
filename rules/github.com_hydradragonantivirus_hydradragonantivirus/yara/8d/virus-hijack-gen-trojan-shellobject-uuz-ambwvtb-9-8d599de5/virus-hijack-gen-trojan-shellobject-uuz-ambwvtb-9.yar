rule Virus_Hijack_Gen_Trojan_ShellObject_uuZ_amBwvTb_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uuZ@amBwvTb_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba07effd2e4e101054820afd872125f77af4ec516dffeaea76179b48152ce8d8"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s3 = "apper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': array([0.80998861, 0.02506225" ascii
    $s4 = "  (dense_1): Linear(in_features=128, " fullword ascii
    $s5 = "  (dense_2): Linear(in_features=128, out_features=1, bias=" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}