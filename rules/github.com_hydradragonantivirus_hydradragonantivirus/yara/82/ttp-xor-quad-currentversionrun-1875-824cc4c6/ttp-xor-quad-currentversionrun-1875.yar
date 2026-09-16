rule TTP_XOR_QUAD_CurrentVersionRun_1875 {
  strings:
    $key_1875 = { 4b 1a [2] 6f 14 [2] 44 38 [2] 6a 1a [2] 7e 01 [2] 71 1b [2] 6f 06 [2] 6d 07 [2] 76 01 [2] 6a 06 [2] 76 29 }

  condition:
    any of them
}