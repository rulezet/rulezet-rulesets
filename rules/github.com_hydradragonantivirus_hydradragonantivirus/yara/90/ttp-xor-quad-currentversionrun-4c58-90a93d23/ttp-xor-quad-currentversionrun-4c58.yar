rule TTP_XOR_QUAD_CurrentVersionRun_4c58 {
  strings:
    $key_4c58 = { 1f 37 [2] 3b 39 [2] 10 15 [2] 3e 37 [2] 2a 2c [2] 25 36 [2] 3b 2b [2] 39 2a [2] 22 2c [2] 3e 2b [2] 22 04 }

  condition:
    any of them
}