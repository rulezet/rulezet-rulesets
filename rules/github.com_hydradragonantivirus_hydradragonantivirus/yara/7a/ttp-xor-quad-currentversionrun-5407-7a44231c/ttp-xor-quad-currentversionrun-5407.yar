rule TTP_XOR_QUAD_CurrentVersionRun_5407 {
  strings:
    $key_5407 = { 07 68 [2] 23 66 [2] 08 4a [2] 26 68 [2] 32 73 [2] 3d 69 [2] 23 74 [2] 21 75 [2] 3a 73 [2] 26 74 [2] 3a 5b }

  condition:
    any of them
}