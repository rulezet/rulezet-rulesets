rule TTP_XOR_MULT_DOSStub_cf76 {
  strings:
    $key_cf76 = { 9b 1e [2] ef 06 [2] a8 04 [2] ef 15 [2] a1 19 [2] ad 13 [2] ba 18 [2] a1 56 [2] 9c }

  condition:
    any of them
}