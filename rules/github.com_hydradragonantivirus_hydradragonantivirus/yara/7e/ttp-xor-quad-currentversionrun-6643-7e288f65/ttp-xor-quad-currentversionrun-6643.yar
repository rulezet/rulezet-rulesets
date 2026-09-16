rule TTP_XOR_QUAD_CurrentVersionRun_6643 {
  strings:
    $key_6643 = { 35 2c [2] 11 22 [2] 3a 0e [2] 14 2c [2] 00 37 [2] 0f 2d [2] 11 30 [2] 13 31 [2] 08 37 [2] 14 30 [2] 08 1f }

  condition:
    any of them
}