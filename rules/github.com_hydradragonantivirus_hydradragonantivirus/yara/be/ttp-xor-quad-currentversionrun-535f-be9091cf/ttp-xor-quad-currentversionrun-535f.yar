rule TTP_XOR_QUAD_CurrentVersionRun_535f {
  strings:
    $key_535f = { 00 30 [2] 24 3e [2] 0f 12 [2] 21 30 [2] 35 2b [2] 3a 31 [2] 24 2c [2] 26 2d [2] 3d 2b [2] 21 2c [2] 3d 03 }

  condition:
    any of them
}