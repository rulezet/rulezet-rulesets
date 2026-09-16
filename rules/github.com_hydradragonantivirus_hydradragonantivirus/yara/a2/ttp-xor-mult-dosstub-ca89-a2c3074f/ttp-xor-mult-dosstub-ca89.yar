rule TTP_XOR_MULT_DOSStub_ca89 {
  strings:
    $key_ca89 = { 9e e1 [2] ea f9 [2] ad fb [2] ea ea [2] a4 e6 [2] a8 ec [2] bf e7 [2] a4 a9 [2] 99 }

  condition:
    any of them
}