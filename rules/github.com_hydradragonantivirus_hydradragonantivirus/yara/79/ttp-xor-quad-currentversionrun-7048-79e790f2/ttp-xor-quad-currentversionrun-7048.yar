rule TTP_XOR_QUAD_CurrentVersionRun_7048 {
  strings:
    $key_7048 = { 23 27 [2] 07 29 [2] 2c 05 [2] 02 27 [2] 16 3c [2] 19 26 [2] 07 3b [2] 05 3a [2] 1e 3c [2] 02 3b [2] 1e 14 }

  condition:
    any of them
}