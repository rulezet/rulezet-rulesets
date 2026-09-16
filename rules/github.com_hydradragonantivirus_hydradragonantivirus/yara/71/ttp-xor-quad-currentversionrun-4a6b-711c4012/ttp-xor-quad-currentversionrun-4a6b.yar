rule TTP_XOR_QUAD_CurrentVersionRun_4a6b {
  strings:
    $key_4a6b = { 19 04 [2] 3d 0a [2] 16 26 [2] 38 04 [2] 2c 1f [2] 23 05 [2] 3d 18 [2] 3f 19 [2] 24 1f [2] 38 18 [2] 24 37 }

  condition:
    any of them
}