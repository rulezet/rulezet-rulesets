rule TTP_XOR_QUAD_CurrentVersionRun_4248 {
  strings:
    $key_4248 = { 11 27 [2] 35 29 [2] 1e 05 [2] 30 27 [2] 24 3c [2] 2b 26 [2] 35 3b [2] 37 3a [2] 2c 3c [2] 30 3b [2] 2c 14 }

  condition:
    any of them
}