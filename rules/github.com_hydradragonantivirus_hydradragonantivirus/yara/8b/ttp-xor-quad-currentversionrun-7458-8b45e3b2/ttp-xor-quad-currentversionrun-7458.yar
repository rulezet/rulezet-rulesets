rule TTP_XOR_QUAD_CurrentVersionRun_7458 {
  strings:
    $key_7458 = { 27 37 [2] 03 39 [2] 28 15 [2] 06 37 [2] 12 2c [2] 1d 36 [2] 03 2b [2] 01 2a [2] 1a 2c [2] 06 2b [2] 1a 04 }

  condition:
    any of them
}