rule TTP_XOR_MULT_DOSStub_cf38 {
  strings:
    $key_cf38 = { 9b 50 [2] ef 48 [2] a8 4a [2] ef 5b [2] a1 57 [2] ad 5d [2] ba 56 [2] a1 18 [2] 9c }

  condition:
    any of them
}