rule TTP_XOR_MULT_DOSStub_ca8b {
  strings:
    $key_ca8b = { 9e e3 [2] ea fb [2] ad f9 [2] ea e8 [2] a4 e4 [2] a8 ee [2] bf e5 [2] a4 ab [2] 99 }

  condition:
    any of them
}