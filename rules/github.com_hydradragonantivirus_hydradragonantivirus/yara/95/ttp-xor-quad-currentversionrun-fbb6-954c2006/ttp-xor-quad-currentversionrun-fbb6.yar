rule TTP_XOR_QUAD_CurrentVersionRun_fbb6 {
  strings:
    $key_fbb6 = { a8 d9 [2] 8c d7 [2] a7 fb [2] 89 d9 [2] 9d c2 [2] 92 d8 [2] 8c c5 [2] 8e c4 [2] 95 c2 [2] 89 c5 [2] 95 ea }

  condition:
    any of them
}