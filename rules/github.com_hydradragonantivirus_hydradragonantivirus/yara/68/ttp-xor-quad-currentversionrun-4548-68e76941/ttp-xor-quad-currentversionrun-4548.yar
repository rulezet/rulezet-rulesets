rule TTP_XOR_QUAD_CurrentVersionRun_4548 {
  strings:
    $key_4548 = { 16 27 [2] 32 29 [2] 19 05 [2] 37 27 [2] 23 3c [2] 2c 26 [2] 32 3b [2] 30 3a [2] 2b 3c [2] 37 3b [2] 2b 14 }

  condition:
    any of them
}