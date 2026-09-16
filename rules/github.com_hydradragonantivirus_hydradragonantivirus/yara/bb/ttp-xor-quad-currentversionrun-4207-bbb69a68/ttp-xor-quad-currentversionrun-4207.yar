rule TTP_XOR_QUAD_CurrentVersionRun_4207 {
  strings:
    $key_4207 = { 11 68 [2] 35 66 [2] 1e 4a [2] 30 68 [2] 24 73 [2] 2b 69 [2] 35 74 [2] 37 75 [2] 2c 73 [2] 30 74 [2] 2c 5b }

  condition:
    any of them
}