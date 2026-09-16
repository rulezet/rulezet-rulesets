rule TTP_XOR_QUAD_CurrentVersionRun_1a43 {
  strings:
    $key_1a43 = { 49 2c [2] 6d 22 [2] 46 0e [2] 68 2c [2] 7c 37 [2] 73 2d [2] 6d 30 [2] 6f 31 [2] 74 37 [2] 68 30 [2] 74 1f }

  condition:
    any of them
}