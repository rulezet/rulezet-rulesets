rule TTP_XOR_QUAD_CurrentVersionRun_4157 {
  strings:
    $key_4157 = { 12 38 [2] 36 36 [2] 1d 1a [2] 33 38 [2] 27 23 [2] 28 39 [2] 36 24 [2] 34 25 [2] 2f 23 [2] 33 24 [2] 2f 0b }

  condition:
    any of them
}