rule TTP_XOR_QUAD_CurrentVersionRun_4a24 {
  strings:
    $key_4a24 = { 19 4b [2] 3d 45 [2] 16 69 [2] 38 4b [2] 2c 50 [2] 23 4a [2] 3d 57 [2] 3f 56 [2] 24 50 [2] 38 57 [2] 24 78 }

  condition:
    any of them
}