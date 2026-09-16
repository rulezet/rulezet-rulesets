rule TTP_XOR_QUAD_CurrentVersionRun_25b4 {
  strings:
    $key_25b4 = { 76 db [2] 52 d5 [2] 79 f9 [2] 57 db [2] 43 c0 [2] 4c da [2] 52 c7 [2] 50 c6 [2] 4b c0 [2] 57 c7 [2] 4b e8 }

  condition:
    any of them
}