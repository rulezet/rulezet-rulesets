rule TTP_XOR_QUAD_CurrentVersionRun_5346 {
  strings:
    $key_5346 = { 00 29 [2] 24 27 [2] 0f 0b [2] 21 29 [2] 35 32 [2] 3a 28 [2] 24 35 [2] 26 34 [2] 3d 32 [2] 21 35 [2] 3d 1a }

  condition:
    any of them
}