rule TTP_XOR_QUAD_CurrentVersionRun_5357 {
  strings:
    $key_5357 = { 00 38 [2] 24 36 [2] 0f 1a [2] 21 38 [2] 35 23 [2] 3a 39 [2] 24 24 [2] 26 25 [2] 3d 23 [2] 21 24 [2] 3d 0b }

  condition:
    any of them
}