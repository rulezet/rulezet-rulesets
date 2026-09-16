rule TTP_XOR_QUAD_CurrentVersionRun_4a25 {
  strings:
    $key_4a25 = { 19 4a [2] 3d 44 [2] 16 68 [2] 38 4a [2] 2c 51 [2] 23 4b [2] 3d 56 [2] 3f 57 [2] 24 51 [2] 38 56 [2] 24 79 }

  condition:
    any of them
}