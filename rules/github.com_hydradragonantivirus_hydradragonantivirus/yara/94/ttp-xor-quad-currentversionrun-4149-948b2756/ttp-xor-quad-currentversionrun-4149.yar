rule TTP_XOR_QUAD_CurrentVersionRun_4149 {
  strings:
    $key_4149 = { 12 26 [2] 36 28 [2] 1d 04 [2] 33 26 [2] 27 3d [2] 28 27 [2] 36 3a [2] 34 3b [2] 2f 3d [2] 33 3a [2] 2f 15 }

  condition:
    any of them
}