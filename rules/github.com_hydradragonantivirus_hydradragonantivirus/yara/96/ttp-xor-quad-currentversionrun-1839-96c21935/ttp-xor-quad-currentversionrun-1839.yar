rule TTP_XOR_QUAD_CurrentVersionRun_1839 {
  strings:
    $key_1839 = { 4b 56 [2] 6f 58 [2] 44 74 [2] 6a 56 [2] 7e 4d [2] 71 57 [2] 6f 4a [2] 6d 4b [2] 76 4d [2] 6a 4a [2] 76 65 }

  condition:
    any of them
}