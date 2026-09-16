rule TTP_XOR_QUAD_CurrentVersionRun_f087 {
  strings:
    $key_f087 = { a3 e8 [2] 87 e6 [2] ac ca [2] 82 e8 [2] 96 f3 [2] 99 e9 [2] 87 f4 [2] 85 f5 [2] 9e f3 [2] 82 f4 [2] 9e db }

  condition:
    any of them
}