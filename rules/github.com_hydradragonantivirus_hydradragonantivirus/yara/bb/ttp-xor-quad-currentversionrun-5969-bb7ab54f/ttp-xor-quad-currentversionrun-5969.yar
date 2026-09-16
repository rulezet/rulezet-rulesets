rule TTP_XOR_QUAD_CurrentVersionRun_5969 {
  strings:
    $key_5969 = { 0a 06 [2] 2e 08 [2] 05 24 [2] 2b 06 [2] 3f 1d [2] 30 07 [2] 2e 1a [2] 2c 1b [2] 37 1d [2] 2b 1a [2] 37 35 }

  condition:
    any of them
}