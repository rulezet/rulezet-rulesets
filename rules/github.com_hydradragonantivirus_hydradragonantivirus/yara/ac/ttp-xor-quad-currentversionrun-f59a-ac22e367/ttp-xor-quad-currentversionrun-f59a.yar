rule TTP_XOR_QUAD_CurrentVersionRun_f59a {
  strings:
    $key_f59a = { a6 f5 [2] 82 fb [2] a9 d7 [2] 87 f5 [2] 93 ee [2] 9c f4 [2] 82 e9 [2] 80 e8 [2] 9b ee [2] 87 e9 [2] 9b c6 }

  condition:
    any of them
}