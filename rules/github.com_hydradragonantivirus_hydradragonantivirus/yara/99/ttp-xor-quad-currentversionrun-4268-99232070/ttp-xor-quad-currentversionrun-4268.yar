rule TTP_XOR_QUAD_CurrentVersionRun_4268 {
  strings:
    $key_4268 = { 11 07 [2] 35 09 [2] 1e 25 [2] 30 07 [2] 24 1c [2] 2b 06 [2] 35 1b [2] 37 1a [2] 2c 1c [2] 30 1b [2] 2c 34 }

  condition:
    any of them
}