rule TTP_XOR_QUAD_CurrentVersionRun_ae9a {
  strings:
    $key_ae9a = { fd f5 [2] d9 fb [2] f2 d7 [2] dc f5 [2] c8 ee [2] c7 f4 [2] d9 e9 [2] db e8 [2] c0 ee [2] dc e9 [2] c0 c6 }

  condition:
    any of them
}