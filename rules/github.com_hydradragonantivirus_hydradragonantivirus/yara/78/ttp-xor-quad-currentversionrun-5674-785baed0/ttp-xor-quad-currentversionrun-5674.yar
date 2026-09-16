rule TTP_XOR_QUAD_CurrentVersionRun_5674 {
  strings:
    $key_5674 = { 05 1b [2] 21 15 [2] 0a 39 [2] 24 1b [2] 30 00 [2] 3f 1a [2] 21 07 [2] 23 06 [2] 38 00 [2] 24 07 [2] 38 28 }

  condition:
    any of them
}