rule TTP_XOR_QUAD_CurrentVersionRun_1867 {
  strings:
    $key_1867 = { 4b 08 [2] 6f 06 [2] 44 2a [2] 6a 08 [2] 7e 13 [2] 71 09 [2] 6f 14 [2] 6d 15 [2] 76 13 [2] 6a 14 [2] 76 3b }

  condition:
    any of them
}