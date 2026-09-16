rule TTP_XOR_MULT_DOSStub_cf96 {
  strings:
    $key_cf96 = { 9b fe [2] ef e6 [2] a8 e4 [2] ef f5 [2] a1 f9 [2] ad f3 [2] ba f8 [2] a1 b6 [2] 9c }

  condition:
    any of them
}