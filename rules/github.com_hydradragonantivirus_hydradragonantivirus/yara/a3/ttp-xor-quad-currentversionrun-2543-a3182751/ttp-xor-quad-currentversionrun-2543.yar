rule TTP_XOR_QUAD_CurrentVersionRun_2543 {
  strings:
    $key_2543 = { 76 2c [2] 52 22 [2] 79 0e [2] 57 2c [2] 43 37 [2] 4c 2d [2] 52 30 [2] 50 31 [2] 4b 37 [2] 57 30 [2] 4b 1f }

  condition:
    any of them
}