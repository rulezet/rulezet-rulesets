rule TTP_XOR_QUAD_CurrentVersionRun_4345 {
  strings:
    $key_4345 = { 10 2a [2] 34 24 [2] 1f 08 [2] 31 2a [2] 25 31 [2] 2a 2b [2] 34 36 [2] 36 37 [2] 2d 31 [2] 31 36 [2] 2d 19 }

  condition:
    any of them
}