rule TTP_XOR_QUAD_CurrentVersionRun_4a04 {
  strings:
    $key_4a04 = { 19 6b [2] 3d 65 [2] 16 49 [2] 38 6b [2] 2c 70 [2] 23 6a [2] 3d 77 [2] 3f 76 [2] 24 70 [2] 38 77 [2] 24 58 }

  condition:
    any of them
}