rule TTP_XOR_QUAD_CurrentVersionRun_4244 {
  strings:
    $key_4244 = { 11 2b [2] 35 25 [2] 1e 09 [2] 30 2b [2] 24 30 [2] 2b 2a [2] 35 37 [2] 37 36 [2] 2c 30 [2] 30 37 [2] 2c 18 }

  condition:
    any of them
}