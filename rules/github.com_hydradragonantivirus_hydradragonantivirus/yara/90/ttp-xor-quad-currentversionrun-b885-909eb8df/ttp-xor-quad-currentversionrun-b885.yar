rule TTP_XOR_QUAD_CurrentVersionRun_b885 {
  strings:
    $key_b885 = { eb ea [2] cf e4 [2] e4 c8 [2] ca ea [2] de f1 [2] d1 eb [2] cf f6 [2] cd f7 [2] d6 f1 [2] ca f6 [2] d6 d9 }

  condition:
    any of them
}