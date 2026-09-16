rule TTP_XOR_QUAD_CurrentVersionRun_f29a {
  strings:
    $key_f29a = { a1 f5 [2] 85 fb [2] ae d7 [2] 80 f5 [2] 94 ee [2] 9b f4 [2] 85 e9 [2] 87 e8 [2] 9c ee [2] 80 e9 [2] 9c c6 }

  condition:
    any of them
}