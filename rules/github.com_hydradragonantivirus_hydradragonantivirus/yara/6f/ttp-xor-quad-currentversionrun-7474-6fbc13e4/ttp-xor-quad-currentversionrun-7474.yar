rule TTP_XOR_QUAD_CurrentVersionRun_7474 {
  strings:
    $key_7474 = { 27 1b [2] 03 15 [2] 28 39 [2] 06 1b [2] 12 00 [2] 1d 1a [2] 03 07 [2] 01 06 [2] 1a 00 [2] 06 07 [2] 1a 28 }

  condition:
    any of them
}