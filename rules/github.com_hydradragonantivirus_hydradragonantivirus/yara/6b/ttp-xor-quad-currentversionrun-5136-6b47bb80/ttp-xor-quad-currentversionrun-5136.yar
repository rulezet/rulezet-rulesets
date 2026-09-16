rule TTP_XOR_QUAD_CurrentVersionRun_5136 {
  strings:
    $key_5136 = { 02 59 [2] 26 57 [2] 0d 7b [2] 23 59 [2] 37 42 [2] 38 58 [2] 26 45 [2] 24 44 [2] 3f 42 [2] 23 45 [2] 3f 6a }

  condition:
    any of them
}