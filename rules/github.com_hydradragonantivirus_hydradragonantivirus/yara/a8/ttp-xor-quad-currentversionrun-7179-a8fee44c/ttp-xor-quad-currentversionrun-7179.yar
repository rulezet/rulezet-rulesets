rule TTP_XOR_QUAD_CurrentVersionRun_7179 {
  strings:
    $key_7179 = { 22 16 [2] 06 18 [2] 2d 34 [2] 03 16 [2] 17 0d [2] 18 17 [2] 06 0a [2] 04 0b [2] 1f 0d [2] 03 0a [2] 1f 25 }

  condition:
    any of them
}