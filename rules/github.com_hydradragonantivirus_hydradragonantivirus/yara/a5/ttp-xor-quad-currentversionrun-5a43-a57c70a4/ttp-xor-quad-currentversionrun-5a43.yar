rule TTP_XOR_QUAD_CurrentVersionRun_5a43 {
  strings:
    $key_5a43 = { 09 2c [2] 2d 22 [2] 06 0e [2] 28 2c [2] 3c 37 [2] 33 2d [2] 2d 30 [2] 2f 31 [2] 34 37 [2] 28 30 [2] 34 1f }

  condition:
    any of them
}