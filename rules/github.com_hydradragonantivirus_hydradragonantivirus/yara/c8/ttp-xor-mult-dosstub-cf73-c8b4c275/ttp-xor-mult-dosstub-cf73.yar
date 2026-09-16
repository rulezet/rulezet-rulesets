rule TTP_XOR_MULT_DOSStub_cf73 {
  strings:
    $key_cf73 = { 9b 1b [2] ef 03 [2] a8 01 [2] ef 10 [2] a1 1c [2] ad 16 [2] ba 1d [2] a1 53 [2] 9c }

  condition:
    any of them
}