rule TTP_XOR_QUAD_CurrentVersionRun_7349 {
  strings:
    $key_7349 = { 20 26 [2] 04 28 [2] 2f 04 [2] 01 26 [2] 15 3d [2] 1a 27 [2] 04 3a [2] 06 3b [2] 1d 3d [2] 01 3a [2] 1d 15 }

  condition:
    any of them
}