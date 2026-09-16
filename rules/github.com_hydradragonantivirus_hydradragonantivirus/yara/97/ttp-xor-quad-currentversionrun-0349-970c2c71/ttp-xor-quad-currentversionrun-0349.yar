rule TTP_XOR_QUAD_CurrentVersionRun_0349 {
  strings:
    $key_0349 = { 50 26 [2] 74 28 [2] 5f 04 [2] 71 26 [2] 65 3d [2] 6a 27 [2] 74 3a [2] 76 3b [2] 6d 3d [2] 71 3a [2] 6d 15 }

  condition:
    any of them
}