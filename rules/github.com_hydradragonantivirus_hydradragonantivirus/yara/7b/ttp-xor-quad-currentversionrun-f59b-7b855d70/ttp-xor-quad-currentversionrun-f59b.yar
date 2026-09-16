rule TTP_XOR_QUAD_CurrentVersionRun_f59b {
  strings:
    $key_f59b = { a6 f4 [2] 82 fa [2] a9 d6 [2] 87 f4 [2] 93 ef [2] 9c f5 [2] 82 e8 [2] 80 e9 [2] 9b ef [2] 87 e8 [2] 9b c7 }

  condition:
    any of them
}