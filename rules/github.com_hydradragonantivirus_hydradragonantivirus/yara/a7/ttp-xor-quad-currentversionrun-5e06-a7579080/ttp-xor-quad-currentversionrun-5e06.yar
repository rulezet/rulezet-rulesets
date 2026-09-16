rule TTP_XOR_QUAD_CurrentVersionRun_5e06 {
  strings:
    $key_5e06 = { 0d 69 [2] 29 67 [2] 02 4b [2] 2c 69 [2] 38 72 [2] 37 68 [2] 29 75 [2] 2b 74 [2] 30 72 [2] 2c 75 [2] 30 5a }

  condition:
    any of them
}