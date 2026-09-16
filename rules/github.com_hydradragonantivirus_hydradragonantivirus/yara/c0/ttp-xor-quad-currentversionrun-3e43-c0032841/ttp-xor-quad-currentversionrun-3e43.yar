rule TTP_XOR_QUAD_CurrentVersionRun_3e43 {
  strings:
    $key_3e43 = { 6d 2c [2] 49 22 [2] 62 0e [2] 4c 2c [2] 58 37 [2] 57 2d [2] 49 30 [2] 4b 31 [2] 50 37 [2] 4c 30 [2] 50 1f }

  condition:
    any of them
}