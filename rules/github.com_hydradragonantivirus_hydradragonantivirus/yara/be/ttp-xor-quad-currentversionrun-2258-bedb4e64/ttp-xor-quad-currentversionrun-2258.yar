rule TTP_XOR_QUAD_CurrentVersionRun_2258 {
  strings:
    $key_2258 = { 71 37 [2] 55 39 [2] 7e 15 [2] 50 37 [2] 44 2c [2] 4b 36 [2] 55 2b [2] 57 2a [2] 4c 2c [2] 50 2b [2] 4c 04 }

  condition:
    any of them
}