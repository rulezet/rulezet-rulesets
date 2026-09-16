rule TTP_XOR_QUAD_CurrentVersionRun_b837 {
  strings:
    $key_b837 = { eb 58 [2] cf 56 [2] e4 7a [2] ca 58 [2] de 43 [2] d1 59 [2] cf 44 [2] cd 45 [2] d6 43 [2] ca 44 [2] d6 6b }

  condition:
    any of them
}