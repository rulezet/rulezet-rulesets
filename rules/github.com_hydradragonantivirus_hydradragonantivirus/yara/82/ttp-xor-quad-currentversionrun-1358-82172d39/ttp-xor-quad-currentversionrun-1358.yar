rule TTP_XOR_QUAD_CurrentVersionRun_1358 {
  strings:
    $key_1358 = { 40 37 [2] 64 39 [2] 4f 15 [2] 61 37 [2] 75 2c [2] 7a 36 [2] 64 2b [2] 66 2a [2] 7d 2c [2] 61 2b [2] 7d 04 }

  condition:
    any of them
}