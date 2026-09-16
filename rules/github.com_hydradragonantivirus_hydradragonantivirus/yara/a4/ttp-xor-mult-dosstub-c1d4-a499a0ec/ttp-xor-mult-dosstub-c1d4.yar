rule TTP_XOR_MULT_DOSStub_c1d4 {
  strings:
    $key_c1d4 = { 95 bc [2] e1 a4 [2] a6 a6 [2] e1 b7 [2] af bb [2] a3 b1 [2] b4 ba [2] af f4 [2] 92 }

  condition:
    any of them
}