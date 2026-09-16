rule TTP_XOR_QUAD_CurrentVersionRun_d49a {
  strings:
    $key_d49a = { 87 f5 [2] a3 fb [2] 88 d7 [2] a6 f5 [2] b2 ee [2] bd f4 [2] a3 e9 [2] a1 e8 [2] ba ee [2] a6 e9 [2] ba c6 }

  condition:
    any of them
}