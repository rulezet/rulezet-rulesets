rule TTP_XOR_QUAD_CurrentVersionRun_4a49 {
  strings:
    $key_4a49 = { 19 26 [2] 3d 28 [2] 16 04 [2] 38 26 [2] 2c 3d [2] 23 27 [2] 3d 3a [2] 3f 3b [2] 24 3d [2] 38 3a [2] 24 15 }

  condition:
    any of them
}