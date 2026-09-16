rule TTP_XOR_MULT_DOSStub_cf20 {
  strings:
    $key_cf20 = { 9b 48 [2] ef 50 [2] a8 52 [2] ef 43 [2] a1 4f [2] ad 45 [2] ba 4e [2] a1 00 [2] 9c }

  condition:
    any of them
}