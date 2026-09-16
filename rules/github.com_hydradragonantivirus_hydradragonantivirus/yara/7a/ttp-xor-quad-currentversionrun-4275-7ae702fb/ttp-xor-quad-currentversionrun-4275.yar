rule TTP_XOR_QUAD_CurrentVersionRun_4275 {
  strings:
    $key_4275 = { 11 1a [2] 35 14 [2] 1e 38 [2] 30 1a [2] 24 01 [2] 2b 1b [2] 35 06 [2] 37 07 [2] 2c 01 [2] 30 06 [2] 2c 29 }

  condition:
    any of them
}