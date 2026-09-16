rule TTP_XOR_QUAD_CurrentVersionRun_b597 {
  strings:
    $key_b597 = { e6 f8 [2] c2 f6 [2] e9 da [2] c7 f8 [2] d3 e3 [2] dc f9 [2] c2 e4 [2] c0 e5 [2] db e3 [2] c7 e4 [2] db cb }

  condition:
    any of them
}