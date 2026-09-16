rule TTP_XOR_QUAD_CurrentVersionRun_3e75 {
  strings:
    $key_3e75 = { 6d 1a [2] 49 14 [2] 62 38 [2] 4c 1a [2] 58 01 [2] 57 1b [2] 49 06 [2] 4b 07 [2] 50 01 [2] 4c 06 [2] 50 29 }

  condition:
    any of them
}