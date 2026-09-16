rule TTP_XOR_QUAD_CurrentVersionRun_2275 {
  strings:
    $key_2275 = { 71 1a [2] 55 14 [2] 7e 38 [2] 50 1a [2] 44 01 [2] 4b 1b [2] 55 06 [2] 57 07 [2] 4c 01 [2] 50 06 [2] 4c 29 }

  condition:
    any of them
}