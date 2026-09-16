rule TTP_XOR_QUAD_CurrentVersionRun_4569 {
  strings:
    $key_4569 = { 16 06 [2] 32 08 [2] 19 24 [2] 37 06 [2] 23 1d [2] 2c 07 [2] 32 1a [2] 30 1b [2] 2b 1d [2] 37 1a [2] 2b 35 }

  condition:
    any of them
}