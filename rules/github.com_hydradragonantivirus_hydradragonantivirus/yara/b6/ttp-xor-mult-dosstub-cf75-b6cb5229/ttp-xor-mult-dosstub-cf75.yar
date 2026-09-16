rule TTP_XOR_MULT_DOSStub_cf75 {
  strings:
    $key_cf75 = { 9b 1d [2] ef 05 [2] a8 07 [2] ef 16 [2] a1 1a [2] ad 10 [2] ba 1b [2] a1 55 [2] 9c }

  condition:
    any of them
}