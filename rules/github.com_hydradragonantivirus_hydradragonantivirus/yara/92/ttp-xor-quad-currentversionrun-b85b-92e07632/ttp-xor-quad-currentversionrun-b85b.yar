rule TTP_XOR_QUAD_CurrentVersionRun_b85b {
  strings:
    $key_b85b = { eb 34 [2] cf 3a [2] e4 16 [2] ca 34 [2] de 2f [2] d1 35 [2] cf 28 [2] cd 29 [2] d6 2f [2] ca 28 [2] d6 07 }

  condition:
    any of them
}