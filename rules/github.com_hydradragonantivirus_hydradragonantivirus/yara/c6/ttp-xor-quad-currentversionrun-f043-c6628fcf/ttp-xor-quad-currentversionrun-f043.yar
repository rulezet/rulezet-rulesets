rule TTP_XOR_QUAD_CurrentVersionRun_f043 {
  strings:
    $key_f043 = { a3 2c [2] 87 22 [2] ac 0e [2] 82 2c [2] 96 37 [2] 99 2d [2] 87 30 [2] 85 31 [2] 9e 37 [2] 82 30 [2] 9e 1f }

  condition:
    any of them
}