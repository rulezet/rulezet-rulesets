rule TTP_XOR_QUAD_CurrentVersionRun_2143 {
  strings:
    $key_2143 = { 72 2c [2] 56 22 [2] 7d 0e [2] 53 2c [2] 47 37 [2] 48 2d [2] 56 30 [2] 54 31 [2] 4f 37 [2] 53 30 [2] 4f 1f }

  condition:
    any of them
}