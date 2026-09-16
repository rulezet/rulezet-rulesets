rule TTP_XOR_QUAD_CurrentVersionRun_0243 {
  strings:
    $key_0243 = { 51 2c [2] 75 22 [2] 5e 0e [2] 70 2c [2] 64 37 [2] 6b 2d [2] 75 30 [2] 77 31 [2] 6c 37 [2] 70 30 [2] 6c 1f }

  condition:
    any of them
}