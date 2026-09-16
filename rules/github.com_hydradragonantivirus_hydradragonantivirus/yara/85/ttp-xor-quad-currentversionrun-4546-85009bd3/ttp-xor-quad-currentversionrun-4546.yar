rule TTP_XOR_QUAD_CurrentVersionRun_4546 {
  strings:
    $key_4546 = { 16 29 [2] 32 27 [2] 19 0b [2] 37 29 [2] 23 32 [2] 2c 28 [2] 32 35 [2] 30 34 [2] 2b 32 [2] 37 35 [2] 2b 1a }

  condition:
    any of them
}