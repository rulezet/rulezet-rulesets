rule TTP_XOR_QUAD_CurrentVersionRun_4369 {
  strings:
    $key_4369 = { 10 06 [2] 34 08 [2] 1f 24 [2] 31 06 [2] 25 1d [2] 2a 07 [2] 34 1a [2] 36 1b [2] 2d 1d [2] 31 1a [2] 2d 35 }

  condition:
    any of them
}