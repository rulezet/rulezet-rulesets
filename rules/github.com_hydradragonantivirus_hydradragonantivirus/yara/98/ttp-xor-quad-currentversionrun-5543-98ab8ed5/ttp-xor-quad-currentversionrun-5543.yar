rule TTP_XOR_QUAD_CurrentVersionRun_5543 {
  strings:
    $key_5543 = { 06 2c [2] 22 22 [2] 09 0e [2] 27 2c [2] 33 37 [2] 3c 2d [2] 22 30 [2] 20 31 [2] 3b 37 [2] 27 30 [2] 3b 1f }

  condition:
    any of them
}