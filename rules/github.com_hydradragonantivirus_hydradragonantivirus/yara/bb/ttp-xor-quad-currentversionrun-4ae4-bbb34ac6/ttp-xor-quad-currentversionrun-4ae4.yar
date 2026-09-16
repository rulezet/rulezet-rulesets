rule TTP_XOR_QUAD_CurrentVersionRun_4ae4 {
  strings:
    $key_4ae4 = { 19 8b [2] 3d 85 [2] 16 a9 [2] 38 8b [2] 2c 90 [2] 23 8a [2] 3d 97 [2] 3f 96 [2] 24 90 [2] 38 97 [2] 24 b8 }

  condition:
    any of them
}