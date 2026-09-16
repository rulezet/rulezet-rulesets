rule TTP_XOR_QUAD_CurrentVersionRun_4c43 {
  strings:
    $key_4c43 = { 1f 2c [2] 3b 22 [2] 10 0e [2] 3e 2c [2] 2a 37 [2] 25 2d [2] 3b 30 [2] 39 31 [2] 22 37 [2] 3e 30 [2] 22 1f }

  condition:
    any of them
}