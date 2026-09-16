rule TTP_XOR_QUAD_CurrentVersionRun_f443 {
  strings:
    $key_f443 = { a7 2c [2] 83 22 [2] a8 0e [2] 86 2c [2] 92 37 [2] 9d 2d [2] 83 30 [2] 81 31 [2] 9a 37 [2] 86 30 [2] 9a 1f }

  condition:
    any of them
}