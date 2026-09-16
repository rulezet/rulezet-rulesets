rule TTP_XOR_QUAD_CurrentVersionRun_2243 {
  strings:
    $key_2243 = { 71 2c [2] 55 22 [2] 7e 0e [2] 50 2c [2] 44 37 [2] 4b 2d [2] 55 30 [2] 57 31 [2] 4c 37 [2] 50 30 [2] 4c 1f }

  condition:
    any of them
}