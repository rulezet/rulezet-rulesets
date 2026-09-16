rule TTP_XOR_QUAD_CurrentVersionRun_b877 {
  strings:
    $key_b877 = { eb 18 [2] cf 16 [2] e4 3a [2] ca 18 [2] de 03 [2] d1 19 [2] cf 04 [2] cd 05 [2] d6 03 [2] ca 04 [2] d6 2b }

  condition:
    any of them
}