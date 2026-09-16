rule TTP_XOR_QUAD_CurrentVersionRun_5a58 {
  strings:
    $key_5a58 = { 09 37 [2] 2d 39 [2] 06 15 [2] 28 37 [2] 3c 2c [2] 33 36 [2] 2d 2b [2] 2f 2a [2] 34 2c [2] 28 2b [2] 34 04 }

  condition:
    any of them
}