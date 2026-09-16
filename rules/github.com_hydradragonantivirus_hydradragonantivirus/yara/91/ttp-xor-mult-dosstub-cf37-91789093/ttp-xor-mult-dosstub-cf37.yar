rule TTP_XOR_MULT_DOSStub_cf37 {
  strings:
    $key_cf37 = { 9b 5f [2] ef 47 [2] a8 45 [2] ef 54 [2] a1 58 [2] ad 52 [2] ba 59 [2] a1 17 [2] 9c }

  condition:
    any of them
}