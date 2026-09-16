rule TTP_XOR_QUAD_CurrentVersionRun_7455 {
  strings:
    $key_7455 = { 27 3a [2] 03 34 [2] 28 18 [2] 06 3a [2] 12 21 [2] 1d 3b [2] 03 26 [2] 01 27 [2] 1a 21 [2] 06 26 [2] 1a 09 }

  condition:
    any of them
}