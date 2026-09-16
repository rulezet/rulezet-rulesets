rule TTP_XOR_QUAD_CurrentVersionRun_5107 {
  strings:
    $key_5107 = { 02 68 [2] 26 66 [2] 0d 4a [2] 23 68 [2] 37 73 [2] 38 69 [2] 26 74 [2] 24 75 [2] 3f 73 [2] 23 74 [2] 3f 5b }

  condition:
    any of them
}