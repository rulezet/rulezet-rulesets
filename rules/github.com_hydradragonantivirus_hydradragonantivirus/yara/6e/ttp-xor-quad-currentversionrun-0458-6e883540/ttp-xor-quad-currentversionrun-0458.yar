rule TTP_XOR_QUAD_CurrentVersionRun_0458 {
  strings:
    $key_0458 = { 57 37 [2] 73 39 [2] 58 15 [2] 76 37 [2] 62 2c [2] 6d 36 [2] 73 2b [2] 71 2a [2] 6a 2c [2] 76 2b [2] 6a 04 }

  condition:
    any of them
}