rule TTP_XOR_MULT_DOSStub_cf45 {
  strings:
    $key_cf45 = { 9b 2d [2] ef 35 [2] a8 37 [2] ef 26 [2] a1 2a [2] ad 20 [2] ba 2b [2] a1 65 [2] 9c }

  condition:
    any of them
}