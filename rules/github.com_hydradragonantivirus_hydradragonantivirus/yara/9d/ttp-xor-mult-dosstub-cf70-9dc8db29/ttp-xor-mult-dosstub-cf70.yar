rule TTP_XOR_MULT_DOSStub_cf70 {
  strings:
    $key_cf70 = { 9b 18 [2] ef 00 [2] a8 02 [2] ef 13 [2] a1 1f [2] ad 15 [2] ba 1e [2] a1 50 [2] 9c }

  condition:
    any of them
}