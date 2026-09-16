rule TTP_XOR_QUAD_CurrentVersionRun_7157 {
  strings:
    $key_7157 = { 22 38 [2] 06 36 [2] 2d 1a [2] 03 38 [2] 17 23 [2] 18 39 [2] 06 24 [2] 04 25 [2] 1f 23 [2] 03 24 [2] 1f 0b }

  condition:
    any of them
}