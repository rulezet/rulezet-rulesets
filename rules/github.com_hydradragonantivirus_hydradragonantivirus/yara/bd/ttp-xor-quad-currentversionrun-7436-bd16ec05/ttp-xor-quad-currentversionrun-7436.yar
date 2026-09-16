rule TTP_XOR_QUAD_CurrentVersionRun_7436 {
  strings:
    $key_7436 = { 27 59 [2] 03 57 [2] 28 7b [2] 06 59 [2] 12 42 [2] 1d 58 [2] 03 45 [2] 01 44 [2] 1a 42 [2] 06 45 [2] 1a 6a }

  condition:
    any of them
}