rule TTP_XOR_QUAD_CurrentVersionRun_3343 {
  strings:
    $key_3343 = { 60 2c [2] 44 22 [2] 6f 0e [2] 41 2c [2] 55 37 [2] 5a 2d [2] 44 30 [2] 46 31 [2] 5d 37 [2] 41 30 [2] 5d 1f }

  condition:
    any of them
}