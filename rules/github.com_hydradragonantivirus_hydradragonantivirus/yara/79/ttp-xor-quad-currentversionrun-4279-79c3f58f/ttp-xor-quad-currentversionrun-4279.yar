rule TTP_XOR_QUAD_CurrentVersionRun_4279 {
  strings:
    $key_4279 = { 11 16 [2] 35 18 [2] 1e 34 [2] 30 16 [2] 24 0d [2] 2b 17 [2] 35 0a [2] 37 0b [2] 2c 0d [2] 30 0a [2] 2c 25 }

  condition:
    any of them
}