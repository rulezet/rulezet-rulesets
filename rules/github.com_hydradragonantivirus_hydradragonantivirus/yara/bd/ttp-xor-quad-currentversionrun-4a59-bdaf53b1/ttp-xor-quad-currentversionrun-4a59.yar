rule TTP_XOR_QUAD_CurrentVersionRun_4a59 {
  strings:
    $key_4a59 = { 19 36 [2] 3d 38 [2] 16 14 [2] 38 36 [2] 2c 2d [2] 23 37 [2] 3d 2a [2] 3f 2b [2] 24 2d [2] 38 2a [2] 24 05 }

  condition:
    any of them
}