rule TTP_XOR_QUAD_CurrentVersionRun_1848 {
  strings:
    $key_1848 = { 4b 27 [2] 6f 29 [2] 44 05 [2] 6a 27 [2] 7e 3c [2] 71 26 [2] 6f 3b [2] 6d 3a [2] 76 3c [2] 6a 3b [2] 76 14 }

  condition:
    any of them
}