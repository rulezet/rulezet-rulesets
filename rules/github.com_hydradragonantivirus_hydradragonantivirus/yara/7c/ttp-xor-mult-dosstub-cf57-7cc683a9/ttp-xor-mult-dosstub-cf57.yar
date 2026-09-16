rule TTP_XOR_MULT_DOSStub_cf57 {
  strings:
    $key_cf57 = { 9b 3f [2] ef 27 [2] a8 25 [2] ef 34 [2] a1 38 [2] ad 32 [2] ba 39 [2] a1 77 [2] 9c }

  condition:
    any of them
}