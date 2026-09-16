rule TTP_XOR_QUAD_CurrentVersionRun_4206 {
  strings:
    $key_4206 = { 11 69 [2] 35 67 [2] 1e 4b [2] 30 69 [2] 24 72 [2] 2b 68 [2] 35 75 [2] 37 74 [2] 2c 72 [2] 30 75 [2] 2c 5a }

  condition:
    any of them
}