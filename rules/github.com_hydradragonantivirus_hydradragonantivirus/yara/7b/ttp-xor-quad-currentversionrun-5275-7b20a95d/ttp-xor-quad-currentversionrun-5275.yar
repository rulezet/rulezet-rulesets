rule TTP_XOR_QUAD_CurrentVersionRun_5275 {
  strings:
    $key_5275 = { 01 1a [2] 25 14 [2] 0e 38 [2] 20 1a [2] 34 01 [2] 3b 1b [2] 25 06 [2] 27 07 [2] 3c 01 [2] 20 06 [2] 3c 29 }

  condition:
    any of them
}