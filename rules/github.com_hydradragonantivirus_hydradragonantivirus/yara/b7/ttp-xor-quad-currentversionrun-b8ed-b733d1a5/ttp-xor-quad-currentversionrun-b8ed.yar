rule TTP_XOR_QUAD_CurrentVersionRun_b8ed {
  strings:
    $key_b8ed = { eb 82 [2] cf 8c [2] e4 a0 [2] ca 82 [2] de 99 [2] d1 83 [2] cf 9e [2] cd 9f [2] d6 99 [2] ca 9e [2] d6 b1 }

  condition:
    any of them
}