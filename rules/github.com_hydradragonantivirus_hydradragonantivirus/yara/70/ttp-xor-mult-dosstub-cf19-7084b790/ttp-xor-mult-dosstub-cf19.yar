rule TTP_XOR_MULT_DOSStub_cf19 {
  strings:
    $key_cf19 = { 9b 71 [2] ef 69 [2] a8 6b [2] ef 7a [2] a1 76 [2] ad 7c [2] ba 77 [2] a1 39 [2] 9c }

  condition:
    any of them
}