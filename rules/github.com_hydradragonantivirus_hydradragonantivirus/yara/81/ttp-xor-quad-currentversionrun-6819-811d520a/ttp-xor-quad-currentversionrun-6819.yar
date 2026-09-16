rule TTP_XOR_QUAD_CurrentVersionRun_6819 {
  strings:
    $key_6819 = { 3b 76 [2] 1f 78 [2] 34 54 [2] 1a 76 [2] 0e 6d [2] 01 77 [2] 1f 6a [2] 1d 6b [2] 06 6d [2] 1a 6a [2] 06 45 }

  condition:
    any of them
}