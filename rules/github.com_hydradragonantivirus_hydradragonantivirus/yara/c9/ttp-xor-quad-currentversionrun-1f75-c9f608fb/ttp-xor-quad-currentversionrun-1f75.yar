rule TTP_XOR_QUAD_CurrentVersionRun_1f75 {
  strings:
    $key_1f75 = { 4c 1a [2] 68 14 [2] 43 38 [2] 6d 1a [2] 79 01 [2] 76 1b [2] 68 06 [2] 6a 07 [2] 71 01 [2] 6d 06 [2] 71 29 }

  condition:
    any of them
}