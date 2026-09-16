rule TTP_XOR_MULT_DOSStub_cf09 {
  strings:
    $key_cf09 = { 9b 61 [2] ef 79 [2] a8 7b [2] ef 6a [2] a1 66 [2] ad 6c [2] ba 67 [2] a1 29 [2] 9c }

  condition:
    any of them
}