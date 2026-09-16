rule TTP_XOR_QUAD_CurrentVersionRun_6407 {
  strings:
    $key_6407 = { 37 68 [2] 13 66 [2] 38 4a [2] 16 68 [2] 02 73 [2] 0d 69 [2] 13 74 [2] 11 75 [2] 0a 73 [2] 16 74 [2] 0a 5b }

  condition:
    any of them
}