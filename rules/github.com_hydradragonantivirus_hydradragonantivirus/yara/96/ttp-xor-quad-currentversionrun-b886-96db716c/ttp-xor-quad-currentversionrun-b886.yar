rule TTP_XOR_QUAD_CurrentVersionRun_b886 {
  strings:
    $key_b886 = { eb e9 [2] cf e7 [2] e4 cb [2] ca e9 [2] de f2 [2] d1 e8 [2] cf f5 [2] cd f4 [2] d6 f2 [2] ca f5 [2] d6 da }

  condition:
    any of them
}