rule TTP_XOR_QUAD_CurrentVersionRun_0358 {
  strings:
    $key_0358 = { 50 37 [2] 74 39 [2] 5f 15 [2] 71 37 [2] 65 2c [2] 6a 36 [2] 74 2b [2] 76 2a [2] 6d 2c [2] 71 2b [2] 6d 04 }

  condition:
    any of them
}