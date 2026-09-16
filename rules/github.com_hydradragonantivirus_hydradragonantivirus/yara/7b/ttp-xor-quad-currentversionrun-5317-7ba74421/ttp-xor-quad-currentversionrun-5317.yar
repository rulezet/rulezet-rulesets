rule TTP_XOR_QUAD_CurrentVersionRun_5317 {
  strings:
    $key_5317 = { 00 78 [2] 24 76 [2] 0f 5a [2] 21 78 [2] 35 63 [2] 3a 79 [2] 24 64 [2] 26 65 [2] 3d 63 [2] 21 64 [2] 3d 4b }

  condition:
    any of them
}