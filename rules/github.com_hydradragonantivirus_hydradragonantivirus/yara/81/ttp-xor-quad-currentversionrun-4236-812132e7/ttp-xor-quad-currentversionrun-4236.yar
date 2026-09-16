rule TTP_XOR_QUAD_CurrentVersionRun_4236 {
  strings:
    $key_4236 = { 11 59 [2] 35 57 [2] 1e 7b [2] 30 59 [2] 24 42 [2] 2b 58 [2] 35 45 [2] 37 44 [2] 2c 42 [2] 30 45 [2] 2c 6a }

  condition:
    any of them
}