rule TTP_XOR_QUAD_CurrentVersionRun_7465 {
  strings:
    $key_7465 = { 27 0a [2] 03 04 [2] 28 28 [2] 06 0a [2] 12 11 [2] 1d 0b [2] 03 16 [2] 01 17 [2] 1a 11 [2] 06 16 [2] 1a 39 }

  condition:
    any of them
}