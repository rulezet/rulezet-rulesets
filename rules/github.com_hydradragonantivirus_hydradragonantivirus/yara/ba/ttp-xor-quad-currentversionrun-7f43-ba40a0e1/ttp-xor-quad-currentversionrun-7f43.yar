rule TTP_XOR_QUAD_CurrentVersionRun_7f43 {
  strings:
    $key_7f43 = { 2c 2c [2] 08 22 [2] 23 0e [2] 0d 2c [2] 19 37 [2] 16 2d [2] 08 30 [2] 0a 31 [2] 11 37 [2] 0d 30 [2] 11 1f }

  condition:
    any of them
}