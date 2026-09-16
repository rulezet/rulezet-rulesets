rule TTP_XOR_QUAD_CurrentVersionRun_7407 {
  strings:
    $key_7407 = { 27 68 [2] 03 66 [2] 28 4a [2] 06 68 [2] 12 73 [2] 1d 69 [2] 03 74 [2] 01 75 [2] 1a 73 [2] 06 74 [2] 1a 5b }

  condition:
    any of them
}