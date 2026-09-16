rule TTP_XOR_QUAD_CurrentVersionRun_cfd4 {
  strings:
    $key_cfd4 = { 9c bb [2] b8 b5 [2] 93 99 [2] bd bb [2] a9 a0 [2] a6 ba [2] b8 a7 [2] ba a6 [2] a1 a0 [2] bd a7 [2] a1 88 }

  condition:
    any of them
}