rule TTP_XOR_QUAD_CurrentVersionRun_5a75 {
  strings:
    $key_5a75 = { 09 1a [2] 2d 14 [2] 06 38 [2] 28 1a [2] 3c 01 [2] 33 1b [2] 2d 06 [2] 2f 07 [2] 34 01 [2] 28 06 [2] 34 29 }

  condition:
    any of them
}