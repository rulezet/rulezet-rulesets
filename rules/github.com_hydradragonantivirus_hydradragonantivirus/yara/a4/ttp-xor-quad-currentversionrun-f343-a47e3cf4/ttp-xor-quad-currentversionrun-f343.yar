rule TTP_XOR_QUAD_CurrentVersionRun_f343 {
  strings:
    $key_f343 = { a0 2c [2] 84 22 [2] af 0e [2] 81 2c [2] 95 37 [2] 9a 2d [2] 84 30 [2] 86 31 [2] 9d 37 [2] 81 30 [2] 9d 1f }

  condition:
    any of them
}