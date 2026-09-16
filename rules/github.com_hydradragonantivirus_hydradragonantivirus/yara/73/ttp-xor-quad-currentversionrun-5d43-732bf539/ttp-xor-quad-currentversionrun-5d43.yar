rule TTP_XOR_QUAD_CurrentVersionRun_5d43 {
  strings:
    $key_5d43 = { 0e 2c [2] 2a 22 [2] 01 0e [2] 2f 2c [2] 3b 37 [2] 34 2d [2] 2a 30 [2] 28 31 [2] 33 37 [2] 2f 30 [2] 33 1f }

  condition:
    any of them
}