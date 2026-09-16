rule TTP_XOR_MULT_DOSStub_cf1f {
  strings:
    $key_cf1f = { 9b 77 [2] ef 6f [2] a8 6d [2] ef 7c [2] a1 70 [2] ad 7a [2] ba 71 [2] a1 3f [2] 9c }

  condition:
    any of them
}