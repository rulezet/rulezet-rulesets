rule TTP_XOR_QUAD_CurrentVersionRun_1847 {
  strings:
    $key_1847 = { 4b 28 [2] 6f 26 [2] 44 0a [2] 6a 28 [2] 7e 33 [2] 71 29 [2] 6f 34 [2] 6d 35 [2] 76 33 [2] 6a 34 [2] 76 1b }

  condition:
    any of them
}