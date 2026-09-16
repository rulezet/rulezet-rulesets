rule TTP_XOR_QUAD_CurrentVersionRun_7444 {
  strings:
    $key_7444 = { 27 2b [2] 03 25 [2] 28 09 [2] 06 2b [2] 12 30 [2] 1d 2a [2] 03 37 [2] 01 36 [2] 1a 30 [2] 06 37 [2] 1a 18 }

  condition:
    any of them
}