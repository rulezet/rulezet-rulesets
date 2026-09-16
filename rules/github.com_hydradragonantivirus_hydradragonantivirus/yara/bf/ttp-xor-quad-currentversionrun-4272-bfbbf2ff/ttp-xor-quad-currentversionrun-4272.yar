rule TTP_XOR_QUAD_CurrentVersionRun_4272 {
  strings:
    $key_4272 = { 11 1d [2] 35 13 [2] 1e 3f [2] 30 1d [2] 24 06 [2] 2b 1c [2] 35 01 [2] 37 00 [2] 2c 06 [2] 30 01 [2] 2c 2e }

  condition:
    any of them
}