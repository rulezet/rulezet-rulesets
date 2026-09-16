rule TTP_XOR_QUAD_CurrentVersionRun_5349 {
  strings:
    $key_5349 = { 00 26 [2] 24 28 [2] 0f 04 [2] 21 26 [2] 35 3d [2] 3a 27 [2] 24 3a [2] 26 3b [2] 3d 3d [2] 21 3a [2] 3d 15 }

  condition:
    any of them
}