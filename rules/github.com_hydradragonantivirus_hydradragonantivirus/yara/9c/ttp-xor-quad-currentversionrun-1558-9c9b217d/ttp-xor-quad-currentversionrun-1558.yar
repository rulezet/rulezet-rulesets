rule TTP_XOR_QUAD_CurrentVersionRun_1558 {
  strings:
    $key_1558 = { 46 37 [2] 62 39 [2] 49 15 [2] 67 37 [2] 73 2c [2] 7c 36 [2] 62 2b [2] 60 2a [2] 7b 2c [2] 67 2b [2] 7b 04 }

  condition:
    any of them
}