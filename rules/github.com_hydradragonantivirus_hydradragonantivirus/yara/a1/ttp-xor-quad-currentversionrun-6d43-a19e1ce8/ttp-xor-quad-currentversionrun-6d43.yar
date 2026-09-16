rule TTP_XOR_QUAD_CurrentVersionRun_6d43 {
  strings:
    $key_6d43 = { 3e 2c [2] 1a 22 [2] 31 0e [2] 1f 2c [2] 0b 37 [2] 04 2d [2] 1a 30 [2] 18 31 [2] 03 37 [2] 1f 30 [2] 03 1f }

  condition:
    any of them
}