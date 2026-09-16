rule TTP_XOR_QUAD_CurrentVersionRun_3148 {
  strings:
    $key_3148 = { 62 27 [2] 46 29 [2] 6d 05 [2] 43 27 [2] 57 3c [2] 58 26 [2] 46 3b [2] 44 3a [2] 5f 3c [2] 43 3b [2] 5f 14 }

  condition:
    any of them
}