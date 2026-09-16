rule TTP_XOR_QUAD_CurrentVersionRun_5e65 {
  strings:
    $key_5e65 = { 0d 0a [2] 29 04 [2] 02 28 [2] 2c 0a [2] 38 11 [2] 37 0b [2] 29 16 [2] 2b 17 [2] 30 11 [2] 2c 16 [2] 30 39 }

  condition:
    any of them
}