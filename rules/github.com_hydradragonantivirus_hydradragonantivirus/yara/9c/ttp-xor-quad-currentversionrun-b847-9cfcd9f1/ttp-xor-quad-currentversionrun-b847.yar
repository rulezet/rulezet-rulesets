rule TTP_XOR_QUAD_CurrentVersionRun_b847 {
  strings:
    $key_b847 = { eb 28 [2] cf 26 [2] e4 0a [2] ca 28 [2] de 33 [2] d1 29 [2] cf 34 [2] cd 35 [2] d6 33 [2] ca 34 [2] d6 1b }

  condition:
    any of them
}