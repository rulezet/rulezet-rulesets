rule TTP_XOR_QUAD_CurrentVersionRun_2d58 {
  strings:
    $key_2d58 = { 7e 37 [2] 5a 39 [2] 71 15 [2] 5f 37 [2] 4b 2c [2] 44 36 [2] 5a 2b [2] 58 2a [2] 43 2c [2] 5f 2b [2] 43 04 }

  condition:
    any of them
}