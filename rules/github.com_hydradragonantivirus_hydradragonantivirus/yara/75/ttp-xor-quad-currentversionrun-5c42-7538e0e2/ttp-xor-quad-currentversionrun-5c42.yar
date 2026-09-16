rule TTP_XOR_QUAD_CurrentVersionRun_5c42 {
  strings:
    $key_5c42 = { 0f 2d [2] 2b 23 [2] 00 0f [2] 2e 2d [2] 3a 36 [2] 35 2c [2] 2b 31 [2] 29 30 [2] 32 36 [2] 2e 31 [2] 32 1e }

  condition:
    any of them
}