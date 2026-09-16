rule TTP_XOR_QUAD_CurrentVersionRun_fb95 {
  strings:
    $key_fb95 = { a8 fa [2] 8c f4 [2] a7 d8 [2] 89 fa [2] 9d e1 [2] 92 fb [2] 8c e6 [2] 8e e7 [2] 95 e1 [2] 89 e6 [2] 95 c9 }

  condition:
    any of them
}