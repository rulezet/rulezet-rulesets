rule TTP_XOR_QUAD_CurrentVersionRun_c087 {
  strings:
    $key_c087 = { 93 e8 [2] b7 e6 [2] 9c ca [2] b2 e8 [2] a6 f3 [2] a9 e9 [2] b7 f4 [2] b5 f5 [2] ae f3 [2] b2 f4 [2] ae db }

  condition:
    any of them
}