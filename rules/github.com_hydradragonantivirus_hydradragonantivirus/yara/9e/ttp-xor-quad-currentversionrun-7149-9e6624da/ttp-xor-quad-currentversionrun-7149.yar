rule TTP_XOR_QUAD_CurrentVersionRun_7149 {
  strings:
    $key_7149 = { 22 26 [2] 06 28 [2] 2d 04 [2] 03 26 [2] 17 3d [2] 18 27 [2] 06 3a [2] 04 3b [2] 1f 3d [2] 03 3a [2] 1f 15 }

  condition:
    any of them
}