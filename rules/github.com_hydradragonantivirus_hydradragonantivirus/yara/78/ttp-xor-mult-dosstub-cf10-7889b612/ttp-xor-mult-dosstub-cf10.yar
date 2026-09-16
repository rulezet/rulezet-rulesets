rule TTP_XOR_MULT_DOSStub_cf10 {
  strings:
    $key_cf10 = { 9b 78 [2] ef 60 [2] a8 62 [2] ef 73 [2] a1 7f [2] ad 75 [2] ba 7e [2] a1 30 [2] 9c }

  condition:
    any of them
}