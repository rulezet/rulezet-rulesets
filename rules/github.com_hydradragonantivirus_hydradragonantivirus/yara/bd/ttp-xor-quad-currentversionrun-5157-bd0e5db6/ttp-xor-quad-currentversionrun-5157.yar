rule TTP_XOR_QUAD_CurrentVersionRun_5157 {
  strings:
    $key_5157 = { 02 38 [2] 26 36 [2] 0d 1a [2] 23 38 [2] 37 23 [2] 38 39 [2] 26 24 [2] 24 25 [2] 3f 23 [2] 23 24 [2] 3f 0b }

  condition:
    any of them
}