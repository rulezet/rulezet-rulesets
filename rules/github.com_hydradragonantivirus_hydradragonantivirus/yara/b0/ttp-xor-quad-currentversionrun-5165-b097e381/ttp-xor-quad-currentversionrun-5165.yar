rule TTP_XOR_QUAD_CurrentVersionRun_5165 {
  strings:
    $key_5165 = { 02 0a [2] 26 04 [2] 0d 28 [2] 23 0a [2] 37 11 [2] 38 0b [2] 26 16 [2] 24 17 [2] 3f 11 [2] 23 16 [2] 3f 39 }

  condition:
    any of them
}