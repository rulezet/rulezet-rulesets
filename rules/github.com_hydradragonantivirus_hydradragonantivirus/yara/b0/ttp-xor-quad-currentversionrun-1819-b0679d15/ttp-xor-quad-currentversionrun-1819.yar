rule TTP_XOR_QUAD_CurrentVersionRun_1819 {
  strings:
    $key_1819 = { 4b 76 [2] 6f 78 [2] 44 54 [2] 6a 76 [2] 7e 6d [2] 71 77 [2] 6f 6a [2] 6d 6b [2] 76 6d [2] 6a 6a [2] 76 45 }

  condition:
    any of them
}