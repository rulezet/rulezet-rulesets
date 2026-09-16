rule TTP_XOR_QUAD_CurrentVersionRun_7139 {
  strings:
    $key_7139 = { 22 56 [2] 06 58 [2] 2d 74 [2] 03 56 [2] 17 4d [2] 18 57 [2] 06 4a [2] 04 4b [2] 1f 4d [2] 03 4a [2] 1f 65 }

  condition:
    any of them
}