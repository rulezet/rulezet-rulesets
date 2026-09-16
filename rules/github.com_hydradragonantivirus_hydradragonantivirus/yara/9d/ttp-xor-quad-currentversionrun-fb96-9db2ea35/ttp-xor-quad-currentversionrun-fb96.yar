rule TTP_XOR_QUAD_CurrentVersionRun_fb96 {
  strings:
    $key_fb96 = { a8 f9 [2] 8c f7 [2] a7 db [2] 89 f9 [2] 9d e2 [2] 92 f8 [2] 8c e5 [2] 8e e4 [2] 95 e2 [2] 89 e5 [2] 95 ca }

  condition:
    any of them
}