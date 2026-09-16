rule TTP_XOR_QUAD_CurrentVersionRun_5f75 {
  strings:
    $key_5f75 = { 0c 1a [2] 28 14 [2] 03 38 [2] 2d 1a [2] 39 01 [2] 36 1b [2] 28 06 [2] 2a 07 [2] 31 01 [2] 2d 06 [2] 31 29 }

  condition:
    any of them
}