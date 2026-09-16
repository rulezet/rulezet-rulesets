rule TTP_XOR_QUAD_CurrentVersionRun_4a09 {
  strings:
    $key_4a09 = { 19 66 [2] 3d 68 [2] 16 44 [2] 38 66 [2] 2c 7d [2] 23 67 [2] 3d 7a [2] 3f 7b [2] 24 7d [2] 38 7a [2] 24 55 }

  condition:
    any of them
}