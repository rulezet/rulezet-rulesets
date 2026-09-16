rule TTP_XOR_MULT_DOSStub_cf78 {
  strings:
    $key_cf78 = { 9b 10 [2] ef 08 [2] a8 0a [2] ef 1b [2] a1 17 [2] ad 1d [2] ba 16 [2] a1 58 [2] 9c }

  condition:
    any of them
}