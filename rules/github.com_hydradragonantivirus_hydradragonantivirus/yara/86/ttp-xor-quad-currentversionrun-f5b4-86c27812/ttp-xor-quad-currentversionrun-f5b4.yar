rule TTP_XOR_QUAD_CurrentVersionRun_f5b4 {
  strings:
    $key_f5b4 = { a6 db [2] 82 d5 [2] a9 f9 [2] 87 db [2] 93 c0 [2] 9c da [2] 82 c7 [2] 80 c6 [2] 9b c0 [2] 87 c7 [2] 9b e8 }

  condition:
    any of them
}