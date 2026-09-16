rule TTP_XOR_QUAD_CurrentVersionRun_7165 {
  strings:
    $key_7165 = { 22 0a [2] 06 04 [2] 2d 28 [2] 03 0a [2] 17 11 [2] 18 0b [2] 06 16 [2] 04 17 [2] 1f 11 [2] 03 16 [2] 1f 39 }

  condition:
    any of them
}