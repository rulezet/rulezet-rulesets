rule TTP_XOR_QUAD_CurrentVersionRun_4158 {
  strings:
    $key_4158 = { 12 37 [2] 36 39 [2] 1d 15 [2] 33 37 [2] 27 2c [2] 28 36 [2] 36 2b [2] 34 2a [2] 2f 2c [2] 33 2b [2] 2f 04 }

  condition:
    any of them
}