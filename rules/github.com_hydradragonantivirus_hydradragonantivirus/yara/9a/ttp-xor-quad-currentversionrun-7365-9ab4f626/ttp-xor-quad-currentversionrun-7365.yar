rule TTP_XOR_QUAD_CurrentVersionRun_7365 {
  strings:
    $key_7365 = { 20 0a [2] 04 04 [2] 2f 28 [2] 01 0a [2] 15 11 [2] 1a 0b [2] 04 16 [2] 06 17 [2] 1d 11 [2] 01 16 [2] 1d 39 }

  condition:
    any of them
}