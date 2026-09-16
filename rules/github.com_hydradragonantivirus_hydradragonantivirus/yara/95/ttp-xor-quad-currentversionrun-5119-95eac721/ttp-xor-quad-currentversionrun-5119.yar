rule TTP_XOR_QUAD_CurrentVersionRun_5119 {
  strings:
    $key_5119 = { 02 76 [2] 26 78 [2] 0d 54 [2] 23 76 [2] 37 6d [2] 38 77 [2] 26 6a [2] 24 6b [2] 3f 6d [2] 23 6a [2] 3f 45 }

  condition:
    any of them
}