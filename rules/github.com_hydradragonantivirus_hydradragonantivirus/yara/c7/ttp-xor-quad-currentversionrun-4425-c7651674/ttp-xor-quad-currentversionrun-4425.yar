rule TTP_XOR_QUAD_CurrentVersionRun_4425 {
  strings:
    $key_4425 = { 17 4a [2] 33 44 [2] 18 68 [2] 36 4a [2] 22 51 [2] 2d 4b [2] 33 56 [2] 31 57 [2] 2a 51 [2] 36 56 [2] 2a 79 }

  condition:
    any of them
}