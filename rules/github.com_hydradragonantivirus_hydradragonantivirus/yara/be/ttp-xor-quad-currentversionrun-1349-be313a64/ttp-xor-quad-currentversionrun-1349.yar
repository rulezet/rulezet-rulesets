rule TTP_XOR_QUAD_CurrentVersionRun_1349 {
  strings:
    $key_1349 = { 40 26 [2] 64 28 [2] 4f 04 [2] 61 26 [2] 75 3d [2] 7a 27 [2] 64 3a [2] 66 3b [2] 7d 3d [2] 61 3a [2] 7d 15 }

  condition:
    any of them
}