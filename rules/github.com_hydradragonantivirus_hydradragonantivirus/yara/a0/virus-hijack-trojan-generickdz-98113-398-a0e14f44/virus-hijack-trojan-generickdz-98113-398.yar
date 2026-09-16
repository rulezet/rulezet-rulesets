rule Virus_Hijack_Trojan_GenericKDZ_98113_398 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_398.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "610c31c89d70a620eff0aebeaeeb16875e4155112e46b9b7b6a03838579f5c05"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "ptimizer': None, @^U" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}