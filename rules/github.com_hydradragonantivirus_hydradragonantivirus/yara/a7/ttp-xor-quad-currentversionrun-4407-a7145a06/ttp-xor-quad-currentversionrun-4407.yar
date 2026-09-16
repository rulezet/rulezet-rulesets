rule TTP_XOR_QUAD_CurrentVersionRun_4407 {
  strings:
    $key_4407 = { 17 68 [2] 33 66 [2] 18 4a [2] 36 68 [2] 22 73 [2] 2d 69 [2] 33 74 [2] 31 75 [2] 2a 73 [2] 36 74 [2] 2a 5b }

  condition:
    any of them
}