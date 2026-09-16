rule TTP_XOR_QUAD_CurrentVersionRun_7143 {
  strings:
    $key_7143 = { 22 2c [2] 06 22 [2] 2d 0e [2] 03 2c [2] 17 37 [2] 18 2d [2] 06 30 [2] 04 31 [2] 1f 37 [2] 03 30 [2] 1f 1f }

  condition:
    any of them
}