rule TTP_XOR_QUAD_CurrentVersionRun_b784 {
  strings:
    $key_b784 = { e4 eb [2] c0 e5 [2] eb c9 [2] c5 eb [2] d1 f0 [2] de ea [2] c0 f7 [2] c2 f6 [2] d9 f0 [2] c5 f7 [2] d9 d8 }

  condition:
    any of them
}