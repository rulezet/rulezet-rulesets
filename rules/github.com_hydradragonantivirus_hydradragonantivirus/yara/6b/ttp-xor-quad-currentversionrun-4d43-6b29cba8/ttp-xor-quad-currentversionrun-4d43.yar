rule TTP_XOR_QUAD_CurrentVersionRun_4d43 {
  strings:
    $key_4d43 = { 1e 2c [2] 3a 22 [2] 11 0e [2] 3f 2c [2] 2b 37 [2] 24 2d [2] 3a 30 [2] 38 31 [2] 23 37 [2] 3f 30 [2] 23 1f }

  condition:
    any of them
}