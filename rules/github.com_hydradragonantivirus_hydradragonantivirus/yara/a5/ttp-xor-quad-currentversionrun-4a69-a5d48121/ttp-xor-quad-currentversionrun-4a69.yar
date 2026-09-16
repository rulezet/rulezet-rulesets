rule TTP_XOR_QUAD_CurrentVersionRun_4a69 {
  strings:
    $key_4a69 = { 19 06 [2] 3d 08 [2] 16 24 [2] 38 06 [2] 2c 1d [2] 23 07 [2] 3d 1a [2] 3f 1b [2] 24 1d [2] 38 1a [2] 24 35 }

  condition:
    any of them
}