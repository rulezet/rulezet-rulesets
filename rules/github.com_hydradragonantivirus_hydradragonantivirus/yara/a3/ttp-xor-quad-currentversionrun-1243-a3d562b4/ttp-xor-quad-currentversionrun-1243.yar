rule TTP_XOR_QUAD_CurrentVersionRun_1243 {
  strings:
    $key_1243 = { 41 2c [2] 65 22 [2] 4e 0e [2] 60 2c [2] 74 37 [2] 7b 2d [2] 65 30 [2] 67 31 [2] 7c 37 [2] 60 30 [2] 7c 1f }

  condition:
    any of them
}