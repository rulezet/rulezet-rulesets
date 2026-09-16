rule TTP_XOR_QUAD_CurrentVersionRun_5843 {
  strings:
    $key_5843 = { 0b 2c [2] 2f 22 [2] 04 0e [2] 2a 2c [2] 3e 37 [2] 31 2d [2] 2f 30 [2] 2d 31 [2] 36 37 [2] 2a 30 [2] 36 1f }

  condition:
    any of them
}