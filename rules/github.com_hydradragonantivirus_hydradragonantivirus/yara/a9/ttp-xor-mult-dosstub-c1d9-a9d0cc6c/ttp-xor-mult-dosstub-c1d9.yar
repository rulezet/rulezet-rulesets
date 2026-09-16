rule TTP_XOR_MULT_DOSStub_c1d9 {
  strings:
    $key_c1d9 = { 95 b1 [2] e1 a9 [2] a6 ab [2] e1 ba [2] af b6 [2] a3 bc [2] b4 b7 [2] af f9 [2] 92 }

  condition:
    any of them
}