rule TTP_XOR_MULT_DOSStub_cf41 {
  strings:
    $key_cf41 = { 9b 29 [2] ef 31 [2] a8 33 [2] ef 22 [2] a1 2e [2] ad 24 [2] ba 2f [2] a1 61 [2] 9c }

  condition:
    any of them
}