rule TTP_XOR_QUAD_CurrentVersionRun_ae94 {
  strings:
    $key_ae94 = { fd fb [2] d9 f5 [2] f2 d9 [2] dc fb [2] c8 e0 [2] c7 fa [2] d9 e7 [2] db e6 [2] c0 e0 [2] dc e7 [2] c0 c8 }

  condition:
    any of them
}