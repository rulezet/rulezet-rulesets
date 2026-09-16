rule TTP_XOR_QUAD_CurrentVersionRun_4565 {
  strings:
    $key_4565 = { 16 0a [2] 32 04 [2] 19 28 [2] 37 0a [2] 23 11 [2] 2c 0b [2] 32 16 [2] 30 17 [2] 2b 11 [2] 37 16 [2] 2b 39 }

  condition:
    any of them
}