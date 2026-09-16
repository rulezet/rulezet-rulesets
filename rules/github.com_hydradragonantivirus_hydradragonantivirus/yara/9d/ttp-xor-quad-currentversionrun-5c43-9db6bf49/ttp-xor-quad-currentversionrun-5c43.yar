rule TTP_XOR_QUAD_CurrentVersionRun_5c43 {
  strings:
    $key_5c43 = { 0f 2c [2] 2b 22 [2] 00 0e [2] 2e 2c [2] 3a 37 [2] 35 2d [2] 2b 30 [2] 29 31 [2] 32 37 [2] 2e 30 [2] 32 1f }

  condition:
    any of them
}