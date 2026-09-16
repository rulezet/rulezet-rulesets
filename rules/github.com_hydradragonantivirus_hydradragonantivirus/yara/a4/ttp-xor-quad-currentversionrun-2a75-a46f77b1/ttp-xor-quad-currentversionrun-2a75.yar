rule TTP_XOR_QUAD_CurrentVersionRun_2a75 {
  strings:
    $key_2a75 = { 79 1a [2] 5d 14 [2] 76 38 [2] 58 1a [2] 4c 01 [2] 43 1b [2] 5d 06 [2] 5f 07 [2] 44 01 [2] 58 06 [2] 44 29 }

  condition:
    any of them
}