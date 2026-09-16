rule TTP_XOR_QUAD_CurrentVersionRun_b860 {
  strings:
    $key_b860 = { eb 0f [2] cf 01 [2] e4 2d [2] ca 0f [2] de 14 [2] d1 0e [2] cf 13 [2] cd 12 [2] d6 14 [2] ca 13 [2] d6 3c }

  condition:
    any of them
}