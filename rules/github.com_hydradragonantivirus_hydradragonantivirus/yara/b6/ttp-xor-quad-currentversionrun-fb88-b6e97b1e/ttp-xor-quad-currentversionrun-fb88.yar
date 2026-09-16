rule TTP_XOR_QUAD_CurrentVersionRun_fb88 {
  strings:
    $key_fb88 = { a8 e7 [2] 8c e9 [2] a7 c5 [2] 89 e7 [2] 9d fc [2] 92 e6 [2] 8c fb [2] 8e fa [2] 95 fc [2] 89 fb [2] 95 d4 }

  condition:
    any of them
}