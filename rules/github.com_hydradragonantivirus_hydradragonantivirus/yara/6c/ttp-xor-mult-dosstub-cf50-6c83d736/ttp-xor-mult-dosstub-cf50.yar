rule TTP_XOR_MULT_DOSStub_cf50 {
  strings:
    $key_cf50 = { 9b 38 [2] ef 20 [2] a8 22 [2] ef 33 [2] a1 3f [2] ad 35 [2] ba 3e [2] a1 70 [2] 9c }

  condition:
    any of them
}