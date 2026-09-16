rule TTP_XOR_MULT_DOSStub_cf49 {
  strings:
    $key_cf49 = { 9b 21 [2] ef 39 [2] a8 3b [2] ef 2a [2] a1 26 [2] ad 2c [2] ba 27 [2] a1 69 [2] 9c }

  condition:
    any of them
}