rule TTP_XOR_QUAD_CurrentVersionRun_4355 {
  strings:
    $key_4355 = { 10 3a [2] 34 34 [2] 1f 18 [2] 31 3a [2] 25 21 [2] 2a 3b [2] 34 26 [2] 36 27 [2] 2d 21 [2] 31 26 [2] 2d 09 }

  condition:
    any of them
}