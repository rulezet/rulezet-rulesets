rule TTP_XOR_QUAD_CurrentVersionRun_0e43 {
  strings:
    $key_0e43 = { 5d 2c [2] 79 22 [2] 52 0e [2] 7c 2c [2] 68 37 [2] 67 2d [2] 79 30 [2] 7b 31 [2] 60 37 [2] 7c 30 [2] 60 1f }

  condition:
    any of them
}