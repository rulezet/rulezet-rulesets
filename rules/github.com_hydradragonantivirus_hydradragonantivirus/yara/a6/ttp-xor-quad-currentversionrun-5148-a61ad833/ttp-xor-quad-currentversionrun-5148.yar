rule TTP_XOR_QUAD_CurrentVersionRun_5148 {
  strings:
    $key_5148 = { 02 27 [2] 26 29 [2] 0d 05 [2] 23 27 [2] 37 3c [2] 38 26 [2] 26 3b [2] 24 3a [2] 3f 3c [2] 23 3b [2] 3f 14 }

  condition:
    any of them
}