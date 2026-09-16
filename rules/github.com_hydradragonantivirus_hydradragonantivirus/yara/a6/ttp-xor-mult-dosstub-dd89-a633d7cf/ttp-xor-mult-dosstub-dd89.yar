rule TTP_XOR_MULT_DOSStub_dd89 {
  strings:
    $key_dd89 = { 89 e1 [2] fd f9 [2] ba fb [2] fd ea [2] b3 e6 [2] bf ec [2] a8 e7 [2] b3 a9 [2] 8e }

  condition:
    any of them
}