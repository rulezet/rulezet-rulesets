rule TTP_XOR_QUAD_CurrentVersionRun_4245 {
  strings:
    $key_4245 = { 11 2a [2] 35 24 [2] 1e 08 [2] 30 2a [2] 24 31 [2] 2b 2b [2] 35 36 [2] 37 37 [2] 2c 31 [2] 30 36 [2] 2c 19 }

  condition:
    any of them
}