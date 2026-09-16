rule TTP_XOR_QUAD_CurrentVersionRun_a685 {
  strings:
    $key_a685 = { f5 ea [2] d1 e4 [2] fa c8 [2] d4 ea [2] c0 f1 [2] cf eb [2] d1 f6 [2] d3 f7 [2] c8 f1 [2] d4 f6 [2] c8 d9 }

  condition:
    any of them
}