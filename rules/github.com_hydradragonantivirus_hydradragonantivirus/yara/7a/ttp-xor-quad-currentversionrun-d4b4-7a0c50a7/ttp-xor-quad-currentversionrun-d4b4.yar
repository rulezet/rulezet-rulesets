rule TTP_XOR_QUAD_CurrentVersionRun_d4b4 {
  strings:
    $key_d4b4 = { 87 db [2] a3 d5 [2] 88 f9 [2] a6 db [2] b2 c0 [2] bd da [2] a3 c7 [2] a1 c6 [2] ba c0 [2] a6 c7 [2] ba e8 }

  condition:
    any of them
}