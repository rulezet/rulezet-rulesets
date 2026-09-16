import "pe"
rule _Virus_Hijack_Backdoor_Hangup_B_281_1_Virus_Hijack_Backdoor_Hang_255 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Backdoor.Hangup.B_281_1.vir, Virus.Hijack_Backdoor.Hangup.B_298_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ffe42a65fd9002191819a656318b0ed90cbd8601f9774c1752041c664006446"
    hash2       = "2e0b028e3d9372b2c0764ef0edb531d366742f2b62eb50084c8501e6cfad7683"

  strings:
    $s1 = "9d:6a:ab:f8:69:2fambda()}, 'x_opt': None, 'f_opt': None, 'x_seq': None, 'f_seq': None, 'attack_classes': 'all', 'y_target': CCla" ascii
    $s2 = "ssifierEnd2EndMalware{'classes': array([0, 1]), 'n_features': 1048576, 'preprocess': None, 'n_jobs': 1, 'model': MalConv(" fullword ascii
    $s3 = "9d:6a:ab:f8:69:2fambda()}, 'x_opt': None, 'f_opt': None, 'x_seq': None, 'f_seq': None, 'attack_classes': 'all', 'y_target': CCla" ascii
    $s4 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s5 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s6 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy',0!" fullword ascii
    $s7 = "ptimizer': None, 'optimizer_scheduler': None, 'epochs': 100, 'plus_version': False, 'train_transform': Lambda()}, 'pro" fullword ascii
    $s8 = "373562336, 0.02033679373562336, 0.02033679373562336, 0.02033679373562336, ': None, 'x_seq': " fullword ascii
    $s9 = "[1.0, 2.864854877770995e-06, 0.00023322011111304164, 0.018210725858807564, 0.0014982939464971423, 0.0009446929325349629, 0.01246" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "cdf5bbb8693f29ef22aef04d2a161dd7" and (all of them)
    ) or (all of them)
}