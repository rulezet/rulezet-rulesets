rule TTP_XOR_QUAD_CurrentVersionRun_4a5b {
  strings:
    $key_4a5b = { 19 34 [2] 3d 3a [2] 16 16 [2] 38 34 [2] 2c 2f [2] 23 35 [2] 3d 28 [2] 3f 29 [2] 24 2f [2] 38 28 [2] 24 07 }

  condition:
    any of them
}