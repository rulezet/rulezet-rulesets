rule TTP_XOR_QUAD_CurrentVersionRun_7145 {
  strings:
    $key_7145 = { 22 2a [2] 06 24 [2] 2d 08 [2] 03 2a [2] 17 31 [2] 18 2b [2] 06 36 [2] 04 37 [2] 1f 31 [2] 03 36 [2] 1f 19 }

  condition:
    any of them
}