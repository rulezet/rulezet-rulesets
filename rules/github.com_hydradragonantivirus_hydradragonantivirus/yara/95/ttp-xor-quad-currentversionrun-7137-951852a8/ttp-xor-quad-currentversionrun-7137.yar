rule TTP_XOR_QUAD_CurrentVersionRun_7137 {
  strings:
    $key_7137 = { 22 58 [2] 06 56 [2] 2d 7a [2] 03 58 [2] 17 43 [2] 18 59 [2] 06 44 [2] 04 45 [2] 1f 43 [2] 03 44 [2] 1f 6b }

  condition:
    any of them
}