rule TTP_XOR_QUAD_CurrentVersionRun_7146 {
  strings:
    $key_7146 = { 22 29 [2] 06 27 [2] 2d 0b [2] 03 29 [2] 17 32 [2] 18 28 [2] 06 35 [2] 04 34 [2] 1f 32 [2] 03 35 [2] 1f 1a }

  condition:
    any of them
}