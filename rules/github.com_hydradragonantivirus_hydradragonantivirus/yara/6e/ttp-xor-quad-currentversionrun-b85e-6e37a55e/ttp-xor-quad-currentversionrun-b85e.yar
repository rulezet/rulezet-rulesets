rule TTP_XOR_QUAD_CurrentVersionRun_b85e {
  strings:
    $key_b85e = { eb 31 [2] cf 3f [2] e4 13 [2] ca 31 [2] de 2a [2] d1 30 [2] cf 2d [2] cd 2c [2] d6 2a [2] ca 2d [2] d6 02 }

  condition:
    any of them
}