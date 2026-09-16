rule TTP_XOR_QUAD_CurrentVersionRun_7b43 {
  strings:
    $key_7b43 = { 28 2c [2] 0c 22 [2] 27 0e [2] 09 2c [2] 1d 37 [2] 12 2d [2] 0c 30 [2] 0e 31 [2] 15 37 [2] 09 30 [2] 15 1f }

  condition:
    any of them
}