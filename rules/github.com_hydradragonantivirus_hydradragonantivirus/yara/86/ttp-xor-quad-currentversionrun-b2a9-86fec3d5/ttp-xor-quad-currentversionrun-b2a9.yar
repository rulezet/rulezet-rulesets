rule TTP_XOR_QUAD_CurrentVersionRun_b2a9 {
  strings:
    $key_b2a9 = { e1 c6 [2] c5 c8 [2] ee e4 [2] c0 c6 [2] d4 dd [2] db c7 [2] c5 da [2] c7 db [2] dc dd [2] c0 da [2] dc f5 }

  condition:
    any of them
}