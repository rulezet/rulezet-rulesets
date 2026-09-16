rule TTP_XOR_MULT_DOSStub_f493 {
  strings:
    $key_f493 = { a0 fb [2] d4 e3 [2] 93 e1 [2] d4 f0 [2] 9a fc [2] 96 f6 [2] 81 fd [2] 9a b3 [2] a7 }

  condition:
    any of them
}