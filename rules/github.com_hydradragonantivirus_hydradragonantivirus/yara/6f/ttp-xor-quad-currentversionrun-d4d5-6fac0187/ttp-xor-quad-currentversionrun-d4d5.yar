rule TTP_XOR_QUAD_CurrentVersionRun_d4d5 {
  strings:
    $key_d4d5 = { 87 ba [2] a3 b4 [2] 88 98 [2] a6 ba [2] b2 a1 [2] bd bb [2] a3 a6 [2] a1 a7 [2] ba a1 [2] a6 a6 [2] ba 89 }

  condition:
    any of them
}