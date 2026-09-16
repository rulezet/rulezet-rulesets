rule TTP_XOR_MULT_DOSStub_cf08 {
  strings:
    $key_cf08 = { 9b 60 [2] ef 78 [2] a8 7a [2] ef 6b [2] a1 67 [2] ad 6d [2] ba 66 [2] a1 28 [2] 9c }

  condition:
    any of them
}