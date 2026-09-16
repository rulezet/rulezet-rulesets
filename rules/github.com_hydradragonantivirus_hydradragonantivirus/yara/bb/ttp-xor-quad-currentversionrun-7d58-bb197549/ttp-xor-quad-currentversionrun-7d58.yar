rule TTP_XOR_QUAD_CurrentVersionRun_7d58 {
  strings:
    $key_7d58 = { 2e 37 [2] 0a 39 [2] 21 15 [2] 0f 37 [2] 1b 2c [2] 14 36 [2] 0a 2b [2] 08 2a [2] 13 2c [2] 0f 2b [2] 13 04 }

  condition:
    any of them
}