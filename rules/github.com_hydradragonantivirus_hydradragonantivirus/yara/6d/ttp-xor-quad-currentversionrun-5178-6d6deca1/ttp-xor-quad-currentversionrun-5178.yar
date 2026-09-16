rule TTP_XOR_QUAD_CurrentVersionRun_5178 {
  strings:
    $key_5178 = { 02 17 [2] 26 19 [2] 0d 35 [2] 23 17 [2] 37 0c [2] 38 16 [2] 26 0b [2] 24 0a [2] 3f 0c [2] 23 0b [2] 3f 24 }

  condition:
    any of them
}