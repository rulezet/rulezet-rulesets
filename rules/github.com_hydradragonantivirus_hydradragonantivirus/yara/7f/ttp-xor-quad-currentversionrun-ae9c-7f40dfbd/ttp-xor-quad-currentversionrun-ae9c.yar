rule TTP_XOR_QUAD_CurrentVersionRun_ae9c {
  strings:
    $key_ae9c = { fd f3 [2] d9 fd [2] f2 d1 [2] dc f3 [2] c8 e8 [2] c7 f2 [2] d9 ef [2] db ee [2] c0 e8 [2] dc ef [2] c0 c0 }

  condition:
    any of them
}