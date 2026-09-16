rule TTP_XOR_QUAD_CurrentVersionRun_5258 {
  strings:
    $key_5258 = { 01 37 [2] 25 39 [2] 0e 15 [2] 20 37 [2] 34 2c [2] 3b 36 [2] 25 2b [2] 27 2a [2] 3c 2c [2] 20 2b [2] 3c 04 }

  condition:
    any of them
}