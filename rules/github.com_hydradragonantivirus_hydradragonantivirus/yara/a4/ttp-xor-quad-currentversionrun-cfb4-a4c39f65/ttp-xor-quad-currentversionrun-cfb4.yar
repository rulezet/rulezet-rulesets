rule TTP_XOR_QUAD_CurrentVersionRun_cfb4 {
  strings:
    $key_cfb4 = { 9c db [2] b8 d5 [2] 93 f9 [2] bd db [2] a9 c0 [2] a6 da [2] b8 c7 [2] ba c6 [2] a1 c0 [2] bd c7 [2] a1 e8 }

  condition:
    any of them
}