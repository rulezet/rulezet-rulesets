rule TTP_XOR_QUAD_CurrentVersionRun_0675 {
  strings:
    $key_0675 = { 55 1a [2] 71 14 [2] 5a 38 [2] 74 1a [2] 60 01 [2] 6f 1b [2] 71 06 [2] 73 07 [2] 68 01 [2] 74 06 [2] 68 29 }

  condition:
    any of them
}