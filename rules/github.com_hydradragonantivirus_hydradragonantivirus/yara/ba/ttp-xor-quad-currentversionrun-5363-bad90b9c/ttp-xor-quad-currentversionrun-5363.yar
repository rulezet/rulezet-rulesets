rule TTP_XOR_QUAD_CurrentVersionRun_5363 {
  strings:
    $key_5363 = { 00 0c [2] 24 02 [2] 0f 2e [2] 21 0c [2] 35 17 [2] 3a 0d [2] 24 10 [2] 26 11 [2] 3d 17 [2] 21 10 [2] 3d 3f }

  condition:
    any of them
}