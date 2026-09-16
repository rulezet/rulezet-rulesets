rule TTP_XOR_QUAD_CurrentVersionRun_b869 {
  strings:
    $key_b869 = { eb 06 [2] cf 08 [2] e4 24 [2] ca 06 [2] de 1d [2] d1 07 [2] cf 1a [2] cd 1b [2] d6 1d [2] ca 1a [2] d6 35 }

  condition:
    any of them
}