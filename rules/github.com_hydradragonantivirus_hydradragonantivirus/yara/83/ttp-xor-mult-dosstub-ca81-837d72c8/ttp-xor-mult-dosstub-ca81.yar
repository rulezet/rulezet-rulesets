rule TTP_XOR_MULT_DOSStub_ca81 {
  strings:
    $key_ca81 = { 9e e9 [2] ea f1 [2] ad f3 [2] ea e2 [2] a4 ee [2] a8 e4 [2] bf ef [2] a4 a1 [2] 99 }

  condition:
    any of them
}