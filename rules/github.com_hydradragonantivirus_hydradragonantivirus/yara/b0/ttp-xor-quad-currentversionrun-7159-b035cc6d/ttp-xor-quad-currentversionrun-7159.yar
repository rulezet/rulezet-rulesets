rule TTP_XOR_QUAD_CurrentVersionRun_7159 {
  strings:
    $key_7159 = { 22 36 [2] 06 38 [2] 2d 14 [2] 03 36 [2] 17 2d [2] 18 37 [2] 06 2a [2] 04 2b [2] 1f 2d [2] 03 2a [2] 1f 05 }

  condition:
    any of them
}