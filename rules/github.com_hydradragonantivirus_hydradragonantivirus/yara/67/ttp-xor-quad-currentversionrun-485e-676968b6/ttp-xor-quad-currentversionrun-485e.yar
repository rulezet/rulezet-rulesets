rule TTP_XOR_QUAD_CurrentVersionRun_485e {
  strings:
    $key_485e = { 1b 31 [2] 3f 3f [2] 14 13 [2] 3a 31 [2] 2e 2a [2] 21 30 [2] 3f 2d [2] 3d 2c [2] 26 2a [2] 3a 2d [2] 26 02 }

  condition:
    any of them
}