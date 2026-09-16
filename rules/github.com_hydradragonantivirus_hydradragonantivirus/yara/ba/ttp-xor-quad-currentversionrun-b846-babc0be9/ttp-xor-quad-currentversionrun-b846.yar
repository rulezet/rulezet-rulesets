rule TTP_XOR_QUAD_CurrentVersionRun_b846 {
  strings:
    $key_b846 = { eb 29 [2] cf 27 [2] e4 0b [2] ca 29 [2] de 32 [2] d1 28 [2] cf 35 [2] cd 34 [2] d6 32 [2] ca 35 [2] d6 1a }

  condition:
    any of them
}