rule TTP_XOR_QUAD_CurrentVersionRun_4a5f {
  strings:
    $key_4a5f = { 19 30 [2] 3d 3e [2] 16 12 [2] 38 30 [2] 2c 2b [2] 23 31 [2] 3d 2c [2] 3f 2d [2] 24 2b [2] 38 2c [2] 24 03 }

  condition:
    any of them
}