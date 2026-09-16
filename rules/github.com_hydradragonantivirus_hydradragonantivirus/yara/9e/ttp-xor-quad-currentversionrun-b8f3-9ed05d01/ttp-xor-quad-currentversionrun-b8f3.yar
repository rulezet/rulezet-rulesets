rule TTP_XOR_QUAD_CurrentVersionRun_b8f3 {
  strings:
    $key_b8f3 = { eb 9c [2] cf 92 [2] e4 be [2] ca 9c [2] de 87 [2] d1 9d [2] cf 80 [2] cd 81 [2] d6 87 [2] ca 80 [2] d6 af }

  condition:
    any of them
}