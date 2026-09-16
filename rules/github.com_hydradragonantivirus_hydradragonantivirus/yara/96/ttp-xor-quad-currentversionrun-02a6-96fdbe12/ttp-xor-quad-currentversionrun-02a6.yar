rule TTP_XOR_QUAD_CurrentVersionRun_02a6 {
  strings:
    $key_02a6 = { 51 c9 [2] 75 c7 [2] 5e eb [2] 70 c9 [2] 64 d2 [2] 6b c8 [2] 75 d5 [2] 77 d4 [2] 6c d2 [2] 70 d5 [2] 6c fa }

  condition:
    any of them
}