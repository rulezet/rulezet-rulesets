rule TTP_XOR_MULT_DOSStub_cf46 {
  strings:
    $key_cf46 = { 9b 2e [2] ef 36 [2] a8 34 [2] ef 25 [2] a1 29 [2] ad 23 [2] ba 28 [2] a1 66 [2] 9c }

  condition:
    any of them
}