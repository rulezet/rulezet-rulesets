rule TTP_XOR_QUAD_CurrentVersionRun_4549 {
  strings:
    $key_4549 = { 16 26 [2] 32 28 [2] 19 04 [2] 37 26 [2] 23 3d [2] 2c 27 [2] 32 3a [2] 30 3b [2] 2b 3d [2] 37 3a [2] 2b 15 }

  condition:
    any of them
}