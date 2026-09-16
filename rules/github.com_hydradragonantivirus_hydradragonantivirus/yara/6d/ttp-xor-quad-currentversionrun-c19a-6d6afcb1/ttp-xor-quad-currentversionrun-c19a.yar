rule TTP_XOR_QUAD_CurrentVersionRun_c19a {
  strings:
    $key_c19a = { 92 f5 [2] b6 fb [2] 9d d7 [2] b3 f5 [2] a7 ee [2] a8 f4 [2] b6 e9 [2] b4 e8 [2] af ee [2] b3 e9 [2] af c6 }

  condition:
    any of them
}