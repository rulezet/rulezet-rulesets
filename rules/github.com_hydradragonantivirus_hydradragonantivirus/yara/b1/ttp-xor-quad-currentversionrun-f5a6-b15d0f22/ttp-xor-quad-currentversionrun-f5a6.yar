rule TTP_XOR_QUAD_CurrentVersionRun_f5a6 {
  strings:
    $key_f5a6 = { a6 c9 [2] 82 c7 [2] a9 eb [2] 87 c9 [2] 93 d2 [2] 9c c8 [2] 82 d5 [2] 80 d4 [2] 9b d2 [2] 87 d5 [2] 9b fa }

  condition:
    any of them
}