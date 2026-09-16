rule TTP_XOR_MULT_DOSStub_cf15 {
  strings:
    $key_cf15 = { 9b 7d [2] ef 65 [2] a8 67 [2] ef 76 [2] a1 7a [2] ad 70 [2] ba 7b [2] a1 35 [2] 9c }

  condition:
    any of them
}