rule TTP_XOR_MULT_DOSStub_cf07 {
  strings:
    $key_cf07 = { 9b 6f [2] ef 77 [2] a8 75 [2] ef 64 [2] a1 68 [2] ad 62 [2] ba 69 [2] a1 27 [2] 9c }

  condition:
    any of them
}