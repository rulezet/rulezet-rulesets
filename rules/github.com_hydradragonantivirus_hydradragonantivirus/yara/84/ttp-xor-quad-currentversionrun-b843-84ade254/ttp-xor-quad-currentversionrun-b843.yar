rule TTP_XOR_QUAD_CurrentVersionRun_b843 {
  strings:
    $key_b843 = { eb 2c [2] cf 22 [2] e4 0e [2] ca 2c [2] de 37 [2] d1 2d [2] cf 30 [2] cd 31 [2] d6 37 [2] ca 30 [2] d6 1f }

  condition:
    any of them
}