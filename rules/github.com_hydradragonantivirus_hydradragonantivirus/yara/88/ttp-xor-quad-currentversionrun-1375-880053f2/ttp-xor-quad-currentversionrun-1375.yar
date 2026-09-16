rule TTP_XOR_QUAD_CurrentVersionRun_1375 {
  strings:
    $key_1375 = { 40 1a [2] 64 14 [2] 4f 38 [2] 61 1a [2] 75 01 [2] 7a 1b [2] 64 06 [2] 66 07 [2] 7d 01 [2] 61 06 [2] 7d 29 }

  condition:
    any of them
}