rule TTP_XOR_QUAD_CurrentVersionRun_f5a8 {
  strings:
    $key_f5a8 = { a6 c7 [2] 82 c9 [2] a9 e5 [2] 87 c7 [2] 93 dc [2] 9c c6 [2] 82 db [2] 80 da [2] 9b dc [2] 87 db [2] 9b f4 }

  condition:
    any of them
}