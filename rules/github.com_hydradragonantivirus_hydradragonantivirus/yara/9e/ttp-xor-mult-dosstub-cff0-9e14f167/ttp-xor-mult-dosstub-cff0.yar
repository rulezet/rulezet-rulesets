rule TTP_XOR_MULT_DOSStub_cff0 {
  strings:
    $key_cff0 = { 9b 98 [2] ef 80 [2] a8 82 [2] ef 93 [2] a1 9f [2] ad 95 [2] ba 9e [2] a1 d0 [2] 9c }

  condition:
    any of them
}