rule TTP_XOR_QUAD_CurrentVersionRun_12a6 {
  strings:
    $key_12a6 = { 41 c9 [2] 65 c7 [2] 4e eb [2] 60 c9 [2] 74 d2 [2] 7b c8 [2] 65 d5 [2] 67 d4 [2] 7c d2 [2] 60 d5 [2] 7c fa }

  condition:
    any of them
}