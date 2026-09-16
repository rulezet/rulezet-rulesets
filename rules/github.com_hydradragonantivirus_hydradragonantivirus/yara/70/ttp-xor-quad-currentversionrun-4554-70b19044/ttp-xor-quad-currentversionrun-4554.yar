rule TTP_XOR_QUAD_CurrentVersionRun_4554 {
  strings:
    $key_4554 = { 16 3b [2] 32 35 [2] 19 19 [2] 37 3b [2] 23 20 [2] 2c 3a [2] 32 27 [2] 30 26 [2] 2b 20 [2] 37 27 [2] 2b 08 }

  condition:
    any of them
}