rule TTP_XOR_QUAD_CurrentVersionRun_7475 {
  strings:
    $key_7475 = { 27 1a [2] 03 14 [2] 28 38 [2] 06 1a [2] 12 01 [2] 1d 1b [2] 03 06 [2] 01 07 [2] 1a 01 [2] 06 06 [2] 1a 29 }

  condition:
    any of them
}