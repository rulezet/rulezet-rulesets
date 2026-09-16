rule TTP_XOR_QUAD_CurrentVersionRun_52a6 {
  strings:
    $key_52a6 = { 01 c9 [2] 25 c7 [2] 0e eb [2] 20 c9 [2] 34 d2 [2] 3b c8 [2] 25 d5 [2] 27 d4 [2] 3c d2 [2] 20 d5 [2] 3c fa }

  condition:
    any of them
}