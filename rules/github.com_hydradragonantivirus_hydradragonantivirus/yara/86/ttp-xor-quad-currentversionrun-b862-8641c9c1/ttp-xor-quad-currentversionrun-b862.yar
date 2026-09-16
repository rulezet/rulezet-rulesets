rule TTP_XOR_QUAD_CurrentVersionRun_b862 {
  strings:
    $key_b862 = { eb 0d [2] cf 03 [2] e4 2f [2] ca 0d [2] de 16 [2] d1 0c [2] cf 11 [2] cd 10 [2] d6 16 [2] ca 11 [2] d6 3e }

  condition:
    any of them
}