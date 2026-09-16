rule TTP_XOR_QUAD_CurrentVersionRun_fb87 {
  strings:
    $key_fb87 = { a8 e8 [2] 8c e6 [2] a7 ca [2] 89 e8 [2] 9d f3 [2] 92 e9 [2] 8c f4 [2] 8e f5 [2] 95 f3 [2] 89 f4 [2] 95 db }

  condition:
    any of them
}