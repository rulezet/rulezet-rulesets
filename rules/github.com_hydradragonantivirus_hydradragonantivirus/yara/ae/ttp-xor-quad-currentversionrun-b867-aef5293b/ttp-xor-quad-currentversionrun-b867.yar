rule TTP_XOR_QUAD_CurrentVersionRun_b867 {
  strings:
    $key_b867 = { eb 08 [2] cf 06 [2] e4 2a [2] ca 08 [2] de 13 [2] d1 09 [2] cf 14 [2] cd 15 [2] d6 13 [2] ca 14 [2] d6 3b }

  condition:
    any of them
}