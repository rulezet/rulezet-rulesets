rule TTP_XOR_QUAD_CurrentVersionRun_b876 {
  strings:
    $key_b876 = { eb 19 [2] cf 17 [2] e4 3b [2] ca 19 [2] de 02 [2] d1 18 [2] cf 05 [2] cd 04 [2] d6 02 [2] ca 05 [2] d6 2a }

  condition:
    any of them
}