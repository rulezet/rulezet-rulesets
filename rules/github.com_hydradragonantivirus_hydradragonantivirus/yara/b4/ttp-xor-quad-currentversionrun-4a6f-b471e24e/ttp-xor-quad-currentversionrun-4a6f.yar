rule TTP_XOR_QUAD_CurrentVersionRun_4a6f {
  strings:
    $key_4a6f = { 19 00 [2] 3d 0e [2] 16 22 [2] 38 00 [2] 2c 1b [2] 23 01 [2] 3d 1c [2] 3f 1d [2] 24 1b [2] 38 1c [2] 24 33 }

  condition:
    any of them
}