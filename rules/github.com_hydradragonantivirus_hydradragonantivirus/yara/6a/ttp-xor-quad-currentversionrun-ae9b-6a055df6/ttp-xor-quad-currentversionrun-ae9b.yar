rule TTP_XOR_QUAD_CurrentVersionRun_ae9b {
  strings:
    $key_ae9b = { fd f4 [2] d9 fa [2] f2 d6 [2] dc f4 [2] c8 ef [2] c7 f5 [2] d9 e8 [2] db e9 [2] c0 ef [2] dc e8 [2] c0 c7 }

  condition:
    any of them
}