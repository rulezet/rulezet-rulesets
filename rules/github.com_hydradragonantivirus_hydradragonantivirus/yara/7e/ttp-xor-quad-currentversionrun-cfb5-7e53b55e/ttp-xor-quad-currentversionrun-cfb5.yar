rule TTP_XOR_QUAD_CurrentVersionRun_cfb5 {
  strings:
    $key_cfb5 = { 9c da [2] b8 d4 [2] 93 f8 [2] bd da [2] a9 c1 [2] a6 db [2] b8 c6 [2] ba c7 [2] a1 c1 [2] bd c6 [2] a1 e9 }

  condition:
    any of them
}