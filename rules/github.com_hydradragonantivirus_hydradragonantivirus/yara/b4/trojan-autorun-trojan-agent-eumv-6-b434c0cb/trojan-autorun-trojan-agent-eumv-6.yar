rule Trojan_Autorun_Trojan_Agent_EUMV_6 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Agent.EUMV_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96a665438f6587e18699ad09d5a9159fc0571dedadad87d2b1787b6ec11fa67c"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "ptimizer': None, @^U" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}