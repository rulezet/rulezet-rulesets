rule TTP_XOR_QUAD_CurrentVersionRun_5125 {
  strings:
    $key_5125 = { 02 4a [2] 26 44 [2] 0d 68 [2] 23 4a [2] 37 51 [2] 38 4b [2] 26 56 [2] 24 57 [2] 3f 51 [2] 23 56 [2] 3f 79 }

  condition:
    any of them
}