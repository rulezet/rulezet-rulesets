rule TTP_XOR_QUAD_CurrentVersionRun_4a5e {
  strings:
    $key_4a5e = { 19 31 [2] 3d 3f [2] 16 13 [2] 38 31 [2] 2c 2a [2] 23 30 [2] 3d 2d [2] 3f 2c [2] 24 2a [2] 38 2d [2] 24 02 }

  condition:
    any of them
}