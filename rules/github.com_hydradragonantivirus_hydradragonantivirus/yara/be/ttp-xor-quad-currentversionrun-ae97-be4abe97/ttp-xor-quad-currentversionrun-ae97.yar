rule TTP_XOR_QUAD_CurrentVersionRun_ae97 {
  strings:
    $key_ae97 = { fd f8 [2] d9 f6 [2] f2 da [2] dc f8 [2] c8 e3 [2] c7 f9 [2] d9 e4 [2] db e5 [2] c0 e3 [2] dc e4 [2] c0 cb }

  condition:
    any of them
}