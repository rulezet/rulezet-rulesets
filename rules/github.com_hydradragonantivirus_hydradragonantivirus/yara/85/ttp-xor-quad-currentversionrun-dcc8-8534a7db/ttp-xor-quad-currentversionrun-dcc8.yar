rule TTP_XOR_QUAD_CurrentVersionRun_dcc8 {
  strings:
    $key_dcc8 = { 8f a7 [2] ab a9 [2] 80 85 [2] ae a7 [2] ba bc [2] b5 a6 [2] ab bb [2] a9 ba [2] b2 bc [2] ae bb [2] b2 94 }

  condition:
    any of them
}