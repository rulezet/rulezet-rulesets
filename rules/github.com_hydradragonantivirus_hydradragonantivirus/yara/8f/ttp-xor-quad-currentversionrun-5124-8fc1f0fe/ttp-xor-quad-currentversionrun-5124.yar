rule TTP_XOR_QUAD_CurrentVersionRun_5124 {
  strings:
    $key_5124 = { 02 4b [2] 26 45 [2] 0d 69 [2] 23 4b [2] 37 50 [2] 38 4a [2] 26 57 [2] 24 56 [2] 3f 50 [2] 23 57 [2] 3f 78 }

  condition:
    any of them
}