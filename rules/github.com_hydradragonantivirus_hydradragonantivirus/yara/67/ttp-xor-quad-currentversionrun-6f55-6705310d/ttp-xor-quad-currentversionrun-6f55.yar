rule TTP_XOR_QUAD_CurrentVersionRun_6f55 {
  strings:
    $key_6f55 = { 3c 3a [2] 18 34 [2] 33 18 [2] 1d 3a [2] 09 21 [2] 06 3b [2] 18 26 [2] 1a 27 [2] 01 21 [2] 1d 26 [2] 01 09 }

  condition:
    any of them
}