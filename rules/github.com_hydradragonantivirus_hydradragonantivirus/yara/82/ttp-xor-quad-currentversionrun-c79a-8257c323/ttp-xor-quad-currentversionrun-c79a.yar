rule TTP_XOR_QUAD_CurrentVersionRun_c79a {
  strings:
    $key_c79a = { 94 f5 [2] b0 fb [2] 9b d7 [2] b5 f5 [2] a1 ee [2] ae f4 [2] b0 e9 [2] b2 e8 [2] a9 ee [2] b5 e9 [2] a9 c6 }

  condition:
    any of them
}