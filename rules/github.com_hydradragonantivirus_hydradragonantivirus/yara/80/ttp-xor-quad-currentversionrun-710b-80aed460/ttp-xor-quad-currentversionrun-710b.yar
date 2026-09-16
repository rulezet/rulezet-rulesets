rule TTP_XOR_QUAD_CurrentVersionRun_710b {
  strings:
    $key_710b = { 22 64 [2] 06 6a [2] 2d 46 [2] 03 64 [2] 17 7f [2] 18 65 [2] 06 78 [2] 04 79 [2] 1f 7f [2] 03 78 [2] 1f 57 }

  condition:
    any of them
}