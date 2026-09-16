rule TTP_XOR_MULT_DOSStub_cf72 {
  strings:
    $key_cf72 = { 9b 1a [2] ef 02 [2] a8 00 [2] ef 11 [2] a1 1d [2] ad 17 [2] ba 1c [2] a1 52 [2] 9c }

  condition:
    any of them
}