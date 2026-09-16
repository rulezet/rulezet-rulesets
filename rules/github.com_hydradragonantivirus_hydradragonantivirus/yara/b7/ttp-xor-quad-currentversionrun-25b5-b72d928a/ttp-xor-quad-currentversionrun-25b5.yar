rule TTP_XOR_QUAD_CurrentVersionRun_25b5 {
  strings:
    $key_25b5 = { 76 da [2] 52 d4 [2] 79 f8 [2] 57 da [2] 43 c1 [2] 4c db [2] 52 c6 [2] 50 c7 [2] 4b c1 [2] 57 c6 [2] 4b e9 }

  condition:
    any of them
}