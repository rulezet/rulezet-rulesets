rule TTP_XOR_QUAD_CurrentVersionRun_f0a6 {
  strings:
    $key_f0a6 = { a3 c9 [2] 87 c7 [2] ac eb [2] 82 c9 [2] 96 d2 [2] 99 c8 [2] 87 d5 [2] 85 d4 [2] 9e d2 [2] 82 d5 [2] 9e fa }

  condition:
    any of them
}