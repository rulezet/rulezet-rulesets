rule TTP_XOR_QUAD_CurrentVersionRun_f5b6 {
  strings:
    $key_f5b6 = { a6 d9 [2] 82 d7 [2] a9 fb [2] 87 d9 [2] 93 c2 [2] 9c d8 [2] 82 c5 [2] 80 c4 [2] 9b c2 [2] 87 c5 [2] 9b ea }

  condition:
    any of them
}