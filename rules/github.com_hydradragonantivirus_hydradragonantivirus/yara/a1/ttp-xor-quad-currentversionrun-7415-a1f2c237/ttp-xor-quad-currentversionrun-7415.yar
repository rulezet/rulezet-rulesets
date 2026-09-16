rule TTP_XOR_QUAD_CurrentVersionRun_7415 {
  strings:
    $key_7415 = { 27 7a [2] 03 74 [2] 28 58 [2] 06 7a [2] 12 61 [2] 1d 7b [2] 03 66 [2] 01 67 [2] 1a 61 [2] 06 66 [2] 1a 49 }

  condition:
    any of them
}