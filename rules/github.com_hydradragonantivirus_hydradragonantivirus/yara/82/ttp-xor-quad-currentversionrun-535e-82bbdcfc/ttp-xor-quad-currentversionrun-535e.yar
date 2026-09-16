rule TTP_XOR_QUAD_CurrentVersionRun_535e {
  strings:
    $key_535e = { 00 31 [2] 24 3f [2] 0f 13 [2] 21 31 [2] 35 2a [2] 3a 30 [2] 24 2d [2] 26 2c [2] 3d 2a [2] 21 2d [2] 3d 02 }

  condition:
    any of them
}