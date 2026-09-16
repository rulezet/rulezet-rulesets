rule TTP_XOR_QUAD_CurrentVersionRun_5e74 {
  strings:
    $key_5e74 = { 0d 1b [2] 29 15 [2] 02 39 [2] 2c 1b [2] 38 00 [2] 37 1a [2] 29 07 [2] 2b 06 [2] 30 00 [2] 2c 07 [2] 30 28 }

  condition:
    any of them
}