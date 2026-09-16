rule TTP_XOR_QUAD_CurrentVersionRun_1a75 {
  strings:
    $key_1a75 = { 49 1a [2] 6d 14 [2] 46 38 [2] 68 1a [2] 7c 01 [2] 73 1b [2] 6d 06 [2] 6f 07 [2] 74 01 [2] 68 06 [2] 74 29 }

  condition:
    any of them
}