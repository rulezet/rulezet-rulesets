rule TTP_XOR_QUAD_CurrentVersionRun_7f46 {
  strings:
    $key_7f46 = { 2c 29 [2] 08 27 [2] 23 0b [2] 0d 29 [2] 19 32 [2] 16 28 [2] 08 35 [2] 0a 34 [2] 11 32 [2] 0d 35 [2] 11 1a }

  condition:
    any of them
}