rule TTP_XOR_QUAD_CurrentVersionRun_b385 {
  strings:
    $key_b385 = { e0 ea [2] c4 e4 [2] ef c8 [2] c1 ea [2] d5 f1 [2] da eb [2] c4 f6 [2] c6 f7 [2] dd f1 [2] c1 f6 [2] dd d9 }

  condition:
    any of them
}