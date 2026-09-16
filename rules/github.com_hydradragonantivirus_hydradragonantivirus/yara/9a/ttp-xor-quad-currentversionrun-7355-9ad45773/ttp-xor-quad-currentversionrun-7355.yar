rule TTP_XOR_QUAD_CurrentVersionRun_7355 {
  strings:
    $key_7355 = { 20 3a [2] 04 34 [2] 2f 18 [2] 01 3a [2] 15 21 [2] 1a 3b [2] 04 26 [2] 06 27 [2] 1d 21 [2] 01 26 [2] 1d 09 }

  condition:
    any of them
}