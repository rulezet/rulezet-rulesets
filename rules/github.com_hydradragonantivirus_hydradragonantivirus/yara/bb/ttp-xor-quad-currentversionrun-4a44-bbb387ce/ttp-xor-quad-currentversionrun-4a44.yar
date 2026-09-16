rule TTP_XOR_QUAD_CurrentVersionRun_4a44 {
  strings:
    $key_4a44 = { 19 2b [2] 3d 25 [2] 16 09 [2] 38 2b [2] 2c 30 [2] 23 2a [2] 3d 37 [2] 3f 36 [2] 24 30 [2] 38 37 [2] 24 18 }

  condition:
    any of them
}