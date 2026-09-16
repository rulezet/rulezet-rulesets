rule TTP_XOR_QUAD_CurrentVersionRun_4259 {
  strings:
    $key_4259 = { 11 36 [2] 35 38 [2] 1e 14 [2] 30 36 [2] 24 2d [2] 2b 37 [2] 35 2a [2] 37 2b [2] 2c 2d [2] 30 2a [2] 2c 05 }

  condition:
    any of them
}