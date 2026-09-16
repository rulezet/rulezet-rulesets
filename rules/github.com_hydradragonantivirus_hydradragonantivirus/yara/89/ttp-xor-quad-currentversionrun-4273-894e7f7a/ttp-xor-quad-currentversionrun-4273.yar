rule TTP_XOR_QUAD_CurrentVersionRun_4273 {
  strings:
    $key_4273 = { 11 1c [2] 35 12 [2] 1e 3e [2] 30 1c [2] 24 07 [2] 2b 1d [2] 35 00 [2] 37 01 [2] 2c 07 [2] 30 00 [2] 2c 2f }

  condition:
    any of them
}