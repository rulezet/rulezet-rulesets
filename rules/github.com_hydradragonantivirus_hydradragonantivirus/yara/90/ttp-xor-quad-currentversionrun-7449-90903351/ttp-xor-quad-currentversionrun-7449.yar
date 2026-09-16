rule TTP_XOR_QUAD_CurrentVersionRun_7449 {
  strings:
    $key_7449 = { 27 26 [2] 03 28 [2] 28 04 [2] 06 26 [2] 12 3d [2] 1d 27 [2] 03 3a [2] 01 3b [2] 1a 3d [2] 06 3a [2] 1a 15 }

  condition:
    any of them
}