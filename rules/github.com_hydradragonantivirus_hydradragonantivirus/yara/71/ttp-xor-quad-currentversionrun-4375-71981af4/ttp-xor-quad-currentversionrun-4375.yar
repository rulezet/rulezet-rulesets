rule TTP_XOR_QUAD_CurrentVersionRun_4375 {
  strings:
    $key_4375 = { 10 1a [2] 34 14 [2] 1f 38 [2] 31 1a [2] 25 01 [2] 2a 1b [2] 34 06 [2] 36 07 [2] 2d 01 [2] 31 06 [2] 2d 29 }

  condition:
    any of them
}