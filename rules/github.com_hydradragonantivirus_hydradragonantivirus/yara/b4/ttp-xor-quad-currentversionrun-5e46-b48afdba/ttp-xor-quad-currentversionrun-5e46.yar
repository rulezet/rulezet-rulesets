rule TTP_XOR_QUAD_CurrentVersionRun_5e46 {
  strings:
    $key_5e46 = { 0d 29 [2] 29 27 [2] 02 0b [2] 2c 29 [2] 38 32 [2] 37 28 [2] 29 35 [2] 2b 34 [2] 30 32 [2] 2c 35 [2] 30 1a }

  condition:
    any of them
}