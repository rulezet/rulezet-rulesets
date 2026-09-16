rule TTP_XOR_QUAD_CurrentVersionRun_714b {
  strings:
    $key_714b = { 22 24 [2] 06 2a [2] 2d 06 [2] 03 24 [2] 17 3f [2] 18 25 [2] 06 38 [2] 04 39 [2] 1f 3f [2] 03 38 [2] 1f 17 }

  condition:
    any of them
}