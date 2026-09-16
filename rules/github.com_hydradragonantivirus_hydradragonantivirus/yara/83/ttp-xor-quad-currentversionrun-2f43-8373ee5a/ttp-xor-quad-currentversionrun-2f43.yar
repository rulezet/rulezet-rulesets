rule TTP_XOR_QUAD_CurrentVersionRun_2f43 {
  strings:
    $key_2f43 = { 7c 2c [2] 58 22 [2] 73 0e [2] 5d 2c [2] 49 37 [2] 46 2d [2] 58 30 [2] 5a 31 [2] 41 37 [2] 5d 30 [2] 41 1f }

  condition:
    any of them
}