rule TTP_XOR_QUAD_CurrentVersionRun_4555 {
  strings:
    $key_4555 = { 16 3a [2] 32 34 [2] 19 18 [2] 37 3a [2] 23 21 [2] 2c 3b [2] 32 26 [2] 30 27 [2] 2b 21 [2] 37 26 [2] 2b 09 }

  condition:
    any of them
}