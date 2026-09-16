rule TTP_XOR_MULT_DOSStub_cf14 {
  strings:
    $key_cf14 = { 9b 7c [2] ef 64 [2] a8 66 [2] ef 77 [2] a1 7b [2] ad 71 [2] ba 7a [2] a1 34 [2] 9c }

  condition:
    any of them
}