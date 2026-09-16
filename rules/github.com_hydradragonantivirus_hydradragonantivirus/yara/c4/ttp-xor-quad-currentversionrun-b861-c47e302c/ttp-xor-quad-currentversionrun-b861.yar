rule TTP_XOR_QUAD_CurrentVersionRun_b861 {
  strings:
    $key_b861 = { eb 0e [2] cf 00 [2] e4 2c [2] ca 0e [2] de 15 [2] d1 0f [2] cf 12 [2] cd 13 [2] d6 15 [2] ca 12 [2] d6 3d }

  condition:
    any of them
}