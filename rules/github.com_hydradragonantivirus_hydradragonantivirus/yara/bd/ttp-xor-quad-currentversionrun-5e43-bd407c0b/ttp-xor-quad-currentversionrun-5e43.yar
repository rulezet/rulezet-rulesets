rule TTP_XOR_QUAD_CurrentVersionRun_5e43 {
  strings:
    $key_5e43 = { 0d 2c [2] 29 22 [2] 02 0e [2] 2c 2c [2] 38 37 [2] 37 2d [2] 29 30 [2] 2b 31 [2] 30 37 [2] 2c 30 [2] 30 1f }

  condition:
    any of them
}