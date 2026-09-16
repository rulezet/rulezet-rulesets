rule TTP_XOR_QUAD_CurrentVersionRun_4a43 {
  strings:
    $key_4a43 = { 19 2c [2] 3d 22 [2] 16 0e [2] 38 2c [2] 2c 37 [2] 23 2d [2] 3d 30 [2] 3f 31 [2] 24 37 [2] 38 30 [2] 24 1f }

  condition:
    any of them
}