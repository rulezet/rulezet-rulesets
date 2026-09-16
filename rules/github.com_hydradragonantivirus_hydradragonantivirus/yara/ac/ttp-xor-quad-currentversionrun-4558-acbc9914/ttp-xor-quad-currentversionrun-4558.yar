rule TTP_XOR_QUAD_CurrentVersionRun_4558 {
  strings:
    $key_4558 = { 16 37 [2] 32 39 [2] 19 15 [2] 37 37 [2] 23 2c [2] 2c 36 [2] 32 2b [2] 30 2a [2] 2b 2c [2] 37 2b [2] 2b 04 }

  condition:
    any of them
}