rule TTP_XOR_QUAD_CurrentVersionRun_e343 {
  strings:
    $key_e343 = { b0 2c [2] 94 22 [2] bf 0e [2] 91 2c [2] 85 37 [2] 8a 2d [2] 94 30 [2] 96 31 [2] 8d 37 [2] 91 30 [2] 8d 1f }

  condition:
    any of them
}