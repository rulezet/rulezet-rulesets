rule TTP_XOR_QUAD_CurrentVersionRun_f49a {
  strings:
    $key_f49a = { a7 f5 [2] 83 fb [2] a8 d7 [2] 86 f5 [2] 92 ee [2] 9d f4 [2] 83 e9 [2] 81 e8 [2] 9a ee [2] 86 e9 [2] 9a c6 }

  condition:
    any of them
}