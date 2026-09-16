rule TTP_XOR_QUAD_CurrentVersionRun_5a07 {
  strings:
    $key_5a07 = { 09 68 [2] 2d 66 [2] 06 4a [2] 28 68 [2] 3c 73 [2] 33 69 [2] 2d 74 [2] 2f 75 [2] 34 73 [2] 28 74 [2] 34 5b }

  condition:
    any of them
}