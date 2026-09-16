rule TTP_XOR_QUAD_CurrentVersionRun_4a4b {
  strings:
    $key_4a4b = { 19 24 [2] 3d 2a [2] 16 06 [2] 38 24 [2] 2c 3f [2] 23 25 [2] 3d 38 [2] 3f 39 [2] 24 3f [2] 38 38 [2] 24 17 }

  condition:
    any of them
}