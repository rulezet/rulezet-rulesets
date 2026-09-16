rule TTP_XOR_QUAD_CurrentVersionRun_7463 {
  strings:
    $key_7463 = { 27 0c [2] 03 02 [2] 28 2e [2] 06 0c [2] 12 17 [2] 1d 0d [2] 03 10 [2] 01 11 [2] 1a 17 [2] 06 10 [2] 1a 3f }

  condition:
    any of them
}