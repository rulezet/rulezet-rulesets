rule TTP_XOR_QUAD_CurrentVersionRun_5274 {
  strings:
    $key_5274 = { 01 1b [2] 25 15 [2] 0e 39 [2] 20 1b [2] 34 00 [2] 3b 1a [2] 25 07 [2] 27 06 [2] 3c 00 [2] 20 07 [2] 3c 28 }

  condition:
    any of them
}