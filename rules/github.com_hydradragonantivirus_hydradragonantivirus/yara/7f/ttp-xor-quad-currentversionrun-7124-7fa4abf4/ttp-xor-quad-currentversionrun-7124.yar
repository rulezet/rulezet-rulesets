rule TTP_XOR_QUAD_CurrentVersionRun_7124 {
  strings:
    $key_7124 = { 22 4b [2] 06 45 [2] 2d 69 [2] 03 4b [2] 17 50 [2] 18 4a [2] 06 57 [2] 04 56 [2] 1f 50 [2] 03 57 [2] 1f 78 }

  condition:
    any of them
}