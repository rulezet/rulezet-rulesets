rule TTP_XOR_QUAD_CurrentVersionRun_1858 {
  strings:
    $key_1858 = { 4b 37 [2] 6f 39 [2] 44 15 [2] 6a 37 [2] 7e 2c [2] 71 36 [2] 6f 2b [2] 6d 2a [2] 76 2c [2] 6a 2b [2] 76 04 }

  condition:
    any of them
}