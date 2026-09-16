rule TTP_XOR_QUAD_CurrentVersionRun_c69a {
  strings:
    $key_c69a = { 95 f5 [2] b1 fb [2] 9a d7 [2] b4 f5 [2] a0 ee [2] af f4 [2] b1 e9 [2] b3 e8 [2] a8 ee [2] b4 e9 [2] a8 c6 }

  condition:
    any of them
}