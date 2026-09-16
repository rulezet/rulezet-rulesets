rule TTP_XOR_QUAD_CurrentVersionRun_32a6 {
  strings:
    $key_32a6 = { 61 c9 [2] 45 c7 [2] 6e eb [2] 40 c9 [2] 54 d2 [2] 5b c8 [2] 45 d5 [2] 47 d4 [2] 5c d2 [2] 40 d5 [2] 5c fa }

  condition:
    any of them
}