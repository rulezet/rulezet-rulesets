rule TTP_XOR_QUAD_CurrentVersionRun_b8f7 {
  strings:
    $key_b8f7 = { eb 98 [2] cf 96 [2] e4 ba [2] ca 98 [2] de 83 [2] d1 99 [2] cf 84 [2] cd 85 [2] d6 83 [2] ca 84 [2] d6 ab }

  condition:
    any of them
}