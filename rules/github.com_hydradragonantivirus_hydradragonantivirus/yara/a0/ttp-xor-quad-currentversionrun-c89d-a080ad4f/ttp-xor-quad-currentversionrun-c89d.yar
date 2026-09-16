rule TTP_XOR_QUAD_CurrentVersionRun_c89d {
  strings:
    $key_c89d = { 9b f2 [2] bf fc [2] 94 d0 [2] ba f2 [2] ae e9 [2] a1 f3 [2] bf ee [2] bd ef [2] a6 e9 [2] ba ee [2] a6 c1 }

  condition:
    any of them
}