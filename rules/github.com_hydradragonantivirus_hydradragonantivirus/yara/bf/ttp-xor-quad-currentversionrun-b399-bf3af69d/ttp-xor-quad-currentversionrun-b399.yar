rule TTP_XOR_QUAD_CurrentVersionRun_b399 {
  strings:
    $key_b399 = { e0 f6 [2] c4 f8 [2] ef d4 [2] c1 f6 [2] d5 ed [2] da f7 [2] c4 ea [2] c6 eb [2] dd ed [2] c1 ea [2] dd c5 }

  condition:
    any of them
}