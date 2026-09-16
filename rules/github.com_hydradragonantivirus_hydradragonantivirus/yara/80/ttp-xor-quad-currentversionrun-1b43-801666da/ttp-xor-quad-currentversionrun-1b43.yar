rule TTP_XOR_QUAD_CurrentVersionRun_1b43 {
  strings:
    $key_1b43 = { 48 2c [2] 6c 22 [2] 47 0e [2] 69 2c [2] 7d 37 [2] 72 2d [2] 6c 30 [2] 6e 31 [2] 75 37 [2] 69 30 [2] 75 1f }

  condition:
    any of them
}