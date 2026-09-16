rule TTP_XOR_QUAD_CurrentVersionRun_c09a {
  strings:
    $key_c09a = { 93 f5 [2] b7 fb [2] 9c d7 [2] b2 f5 [2] a6 ee [2] a9 f4 [2] b7 e9 [2] b5 e8 [2] ae ee [2] b2 e9 [2] ae c6 }

  condition:
    any of them
}