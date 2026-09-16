rule TTP_XOR_QUAD_CurrentVersionRun_4e58 {
  strings:
    $key_4e58 = { 1d 37 [2] 39 39 [2] 12 15 [2] 3c 37 [2] 28 2c [2] 27 36 [2] 39 2b [2] 3b 2a [2] 20 2c [2] 3c 2b [2] 20 04 }

  condition:
    any of them
}