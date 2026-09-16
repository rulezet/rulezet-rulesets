rule TTP_XOR_QUAD_CurrentVersionRun_6358 {
  strings:
    $key_6358 = { 30 37 [2] 14 39 [2] 3f 15 [2] 11 37 [2] 05 2c [2] 0a 36 [2] 14 2b [2] 16 2a [2] 0d 2c [2] 11 2b [2] 0d 04 }

  condition:
    any of them
}