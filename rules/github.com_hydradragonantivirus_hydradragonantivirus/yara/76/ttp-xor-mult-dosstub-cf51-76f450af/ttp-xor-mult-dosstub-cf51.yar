rule TTP_XOR_MULT_DOSStub_cf51 {
  strings:
    $key_cf51 = { 9b 39 [2] ef 21 [2] a8 23 [2] ef 32 [2] a1 3e [2] ad 34 [2] ba 3f [2] a1 71 [2] 9c }

  condition:
    any of them
}