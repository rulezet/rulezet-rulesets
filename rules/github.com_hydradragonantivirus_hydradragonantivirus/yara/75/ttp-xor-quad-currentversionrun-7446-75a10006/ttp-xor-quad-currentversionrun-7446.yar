rule TTP_XOR_QUAD_CurrentVersionRun_7446 {
  strings:
    $key_7446 = { 27 29 [2] 03 27 [2] 28 0b [2] 06 29 [2] 12 32 [2] 1d 28 [2] 03 35 [2] 01 34 [2] 1a 32 [2] 06 35 [2] 1a 1a }

  condition:
    any of them
}