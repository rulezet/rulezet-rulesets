rule TTP_XOR_QUAD_CurrentVersionRun_f243 {
  strings:
    $key_f243 = { a1 2c [2] 85 22 [2] ae 0e [2] 80 2c [2] 94 37 [2] 9b 2d [2] 85 30 [2] 87 31 [2] 9c 37 [2] 80 30 [2] 9c 1f }

  condition:
    any of them
}