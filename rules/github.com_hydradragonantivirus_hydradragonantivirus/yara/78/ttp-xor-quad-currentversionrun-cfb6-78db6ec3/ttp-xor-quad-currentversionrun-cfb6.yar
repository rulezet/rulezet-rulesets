rule TTP_XOR_QUAD_CurrentVersionRun_cfb6 {
  strings:
    $key_cfb6 = { 9c d9 [2] b8 d7 [2] 93 fb [2] bd d9 [2] a9 c2 [2] a6 d8 [2] b8 c5 [2] ba c4 [2] a1 c2 [2] bd c5 [2] a1 ea }

  condition:
    any of them
}