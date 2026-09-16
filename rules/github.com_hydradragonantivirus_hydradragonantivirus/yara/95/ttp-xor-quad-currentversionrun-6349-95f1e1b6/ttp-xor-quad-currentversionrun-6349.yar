rule TTP_XOR_QUAD_CurrentVersionRun_6349 {
  strings:
    $key_6349 = { 30 26 [2] 14 28 [2] 3f 04 [2] 11 26 [2] 05 3d [2] 0a 27 [2] 14 3a [2] 16 3b [2] 0d 3d [2] 11 3a [2] 0d 15 }

  condition:
    any of them
}