rule TTP_XOR_QUAD_CurrentVersionRun_7358 {
  strings:
    $key_7358 = { 20 37 [2] 04 39 [2] 2f 15 [2] 01 37 [2] 15 2c [2] 1a 36 [2] 04 2b [2] 06 2a [2] 1d 2c [2] 01 2b [2] 1d 04 }

  condition:
    any of them
}