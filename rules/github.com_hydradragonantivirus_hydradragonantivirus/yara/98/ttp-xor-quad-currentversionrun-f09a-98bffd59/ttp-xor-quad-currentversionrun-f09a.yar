rule TTP_XOR_QUAD_CurrentVersionRun_f09a {
  strings:
    $key_f09a = { a3 f5 [2] 87 fb [2] ac d7 [2] 82 f5 [2] 96 ee [2] 99 f4 [2] 87 e9 [2] 85 e8 [2] 9e ee [2] 82 e9 [2] 9e c6 }

  condition:
    any of them
}