rule TTP_XOR_MULT_DOSStub_cf12 {
  strings:
    $key_cf12 = { 9b 7a [2] ef 62 [2] a8 60 [2] ef 71 [2] a1 7d [2] ad 77 [2] ba 7c [2] a1 32 [2] 9c }

  condition:
    any of them
}