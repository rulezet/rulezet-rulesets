rule TTP_XOR_QUAD_CurrentVersionRun_6a43 {
  strings:
    $key_6a43 = { 39 2c [2] 1d 22 [2] 36 0e [2] 18 2c [2] 0c 37 [2] 03 2d [2] 1d 30 [2] 1f 31 [2] 04 37 [2] 18 30 [2] 04 1f }

  condition:
    any of them
}