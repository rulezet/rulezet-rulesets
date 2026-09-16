rule Trojan_Danger_Trojan_GenericKD_35816276 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.35816276.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61fa5c3ed830159a929978445efdbe0345a94842106c662d842c0b19f003adf8"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "ptimizer': None, 'optimizer_scheduler': None, 'epochs': 100, 'plus_version': False, 'train_transform': Lambda(), " fullword ascii
    $s3 = "  (dense_1): Linear(in_features=128, out_features=128, bias" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}