rule TTP_XOR_QUAD_CurrentVersionRun_5425 {
  strings:
    $key_5425 = { 07 4a [2] 23 44 [2] 08 68 [2] 26 4a [2] 32 51 [2] 3d 4b [2] 23 56 [2] 21 57 [2] 3a 51 [2] 26 56 [2] 3a 79 }

  condition:
    any of them
}