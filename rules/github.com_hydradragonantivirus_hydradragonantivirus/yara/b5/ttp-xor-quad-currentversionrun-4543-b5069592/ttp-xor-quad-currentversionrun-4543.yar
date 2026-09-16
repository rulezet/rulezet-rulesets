rule TTP_XOR_QUAD_CurrentVersionRun_4543 {
  strings:
    $key_4543 = { 16 2c [2] 32 22 [2] 19 0e [2] 37 2c [2] 23 37 [2] 2c 2d [2] 32 30 [2] 30 31 [2] 2b 37 [2] 37 30 [2] 2b 1f }

  condition:
    any of them
}