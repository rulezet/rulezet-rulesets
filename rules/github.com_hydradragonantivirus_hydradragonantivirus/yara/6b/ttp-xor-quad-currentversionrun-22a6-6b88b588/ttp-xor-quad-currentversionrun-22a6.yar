rule TTP_XOR_QUAD_CurrentVersionRun_22a6 {
  strings:
    $key_22a6 = { 71 c9 [2] 55 c7 [2] 7e eb [2] 50 c9 [2] 44 d2 [2] 4b c8 [2] 55 d5 [2] 57 d4 [2] 4c d2 [2] 50 d5 [2] 4c fa }

  condition:
    any of them
}